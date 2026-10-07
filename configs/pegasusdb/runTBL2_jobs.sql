-- runTBL2_jobs: every column of runTBL2, plus the workload class and the
-- derived columns a query would otherwise have to get right by itself. Each
-- one replaces a trap Cassandra's model fell into writing raw SQL, so the
-- trap is fixed here, once, instead of in a prompt rule or a guard. Created by
-- someone with write rights on pegasusdb; Cassandra's own login is read-only
-- and only reads it. Plan approved by Glen 2026-10-07.
--
-- workload        Same CASE as runTBL2_workload.sql (a test holds the two
--                 together): 'gpu', 'cpu', 'excluded' or 'unclassified'.
-- mem_req_gb,     TRESReq_mem / TRESalloc_mem converted to GB by suffix,
-- mem_alloc_gb    Slurm's convention: T x 1024, G as is, M / 1024 (powers of
--                 1024), and the value is the job's total. Both are Slurm's
--                 convention, not checked against this cluster's config.
--                 NULL when the source is empty or null: memory is recorded
--                 only from 22 January 2026.
-- gpus_req,       TRESReq_gres_gpu / TRESalloc_gres_gpu as a number. 0 when
-- gpus_alloc      memory was recorded and no GPU was; NULL when memory was
--                 not recorded, because then nothing was and 0 would claim a
--                 job asked for no GPU. gpus_alloc is NULL for a job that
--                 never got an allocation.
-- nodes_req       TRESReq_node as a number (NNodes is nodes allocated).
-- timelimit_min   TimelimitRaw as a number of minutes. NULL for UNLIMITED and
--                 Partition (the partition's default), which are not numbers.
-- wait_s          StartTime - SubmitTime, for jobs that started; else NULL.
-- run_s           EndTime - StartTime, for jobs that started and ended; else
--                 NULL. A job that never started has StartTime 0 or NULL, and
--                 subtracting anyway gives a large negative wait.
-- submit_day,     The submit date and 'YYYY-MM' in the session's time zone.
-- submit_month    Cassandra's session uses the server's, US Eastern. Named
--                 zones cannot be used here: CONVERT_TZ(..., 'America/New_York')
--                 returns NULL because the zone tables are not loaded.
-- state_group     State with 'CANCELLED by <uid>' folded into 'CANCELLED'.
-- schoolName,     From groupTBL, whose groupName is its primary key, so the
-- deptName        LEFT JOIN cannot duplicate a job. NULL for a group groupTBL
--                 does not list (the MG- groups, among others). jobs2VIEW uses
--                 an inner join and drops those jobs instead.
--
-- SELECT r.* is expanded when the view is created: if runTBL2 gains columns,
-- re-run this file to include them.

-- ALGORITHM=MERGE: queries against the view are merged into queries against
-- runTBL2, so a SubmitTime bound still uses the SubmitTime index. If a future
-- edit makes the view unmergeable, creation fails rather than silently
-- turning every query into a full scan.
-- SQL SECURITY INVOKER: the view reads with the caller's own rights, so it
-- grants nothing extra and does not depend on the creating account existing.
CREATE OR REPLACE ALGORITHM=MERGE SQL SECURITY INVOKER VIEW runTBL2_jobs AS
SELECT r.*,
  CASE
    WHEN r.`partition` IS NULL OR LOCATE(CHAR(95), r.`partition`) > 0 THEN 'excluded'
    WHEN r.`partition` IN ('nano', 'deus', 'purge', 'secret', 'secret-gpu') THEN 'excluded'
    WHEN r.SubmitTime >= 1778299200 THEN
      CASE WHEN COALESCE(r.TRESReq_gres_gpu, '') NOT IN ('', '0') THEN 'gpu' ELSE 'cpu' END
    WHEN r.`partition` LIKE 'superChip%'
      OR r.`partition` IN ('gpu', 'viz', 'ait', 'small-gpu', 'med-gpu', 'large-gpu', 'ultra-gpu', 'debug-gpu') THEN 'gpu'
    WHEN r.`partition` IN ('cpu', 'highMemInt', 'defq', 'tiny', 'short', '384gb', 'short-384gb',
                           'highMem', 'highThru', 'highCore', 'debug', 'debug-cpu', 'longJob') THEN 'cpu'
    ELSE 'unclassified'
  END AS workload,
  CAST(CASE RIGHT(r.TRESReq_mem, 1)
    WHEN 'T' THEN CAST(LEFT(r.TRESReq_mem, CHAR_LENGTH(r.TRESReq_mem) - 1) AS DECIMAL(20,3)) * 1024
    WHEN 'G' THEN CAST(LEFT(r.TRESReq_mem, CHAR_LENGTH(r.TRESReq_mem) - 1) AS DECIMAL(20,3))
    WHEN 'M' THEN CAST(LEFT(r.TRESReq_mem, CHAR_LENGTH(r.TRESReq_mem) - 1) AS DECIMAL(20,3)) / 1024
  END AS DECIMAL(23,3)) AS mem_req_gb,
  CAST(CASE RIGHT(r.TRESalloc_mem, 1)
    WHEN 'T' THEN CAST(LEFT(r.TRESalloc_mem, CHAR_LENGTH(r.TRESalloc_mem) - 1) AS DECIMAL(20,3)) * 1024
    WHEN 'G' THEN CAST(LEFT(r.TRESalloc_mem, CHAR_LENGTH(r.TRESalloc_mem) - 1) AS DECIMAL(20,3))
    WHEN 'M' THEN CAST(LEFT(r.TRESalloc_mem, CHAR_LENGTH(r.TRESalloc_mem) - 1) AS DECIMAL(20,3)) / 1024
  END AS DECIMAL(23,3)) AS mem_alloc_gb,
  CASE WHEN COALESCE(r.TRESReq_mem, '') = '' THEN NULL
       ELSE CAST(COALESCE(NULLIF(r.TRESReq_gres_gpu, ''), '0') AS UNSIGNED) END AS gpus_req,
  CASE WHEN COALESCE(r.TRESalloc_mem, '') = '' THEN NULL
       ELSE CAST(COALESCE(NULLIF(r.TRESalloc_gres_gpu, ''), '0') AS UNSIGNED) END AS gpus_alloc,
  CAST(NULLIF(r.TRESReq_node, '') AS UNSIGNED) AS nodes_req,
  CASE WHEN r.TimelimitRaw REGEXP '^[0-9]+$' THEN CAST(r.TimelimitRaw AS UNSIGNED) END AS timelimit_min,
  CASE WHEN r.StartTime > 0 THEN r.StartTime - r.SubmitTime END AS wait_s,
  CASE WHEN r.StartTime > 0 AND r.EndTime >= r.StartTime THEN r.EndTime - r.StartTime END AS run_s,
  DATE(FROM_UNIXTIME(r.SubmitTime)) AS submit_day,
  DATE_FORMAT(FROM_UNIXTIME(r.SubmitTime), '%Y-%m') AS submit_month,
  CASE WHEN r.State LIKE 'CANCELLED%' THEN 'CANCELLED' ELSE r.State END AS state_group,
  g.schoolName,
  g.deptName
FROM runTBL2 r
LEFT JOIN groupTBL g ON g.groupName = r.groupName;
