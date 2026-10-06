-- runTBL2_workload: runTBL2 plus one column, `workload`, classifying each job
-- as 'gpu', 'cpu', 'excluded' or 'unclassified', by the rules Glen set on
-- 2026-10-06. Created by someone with write rights on pegasusdb; Cassandra's
-- own login is read-only and only reads it.
--
-- From 9 May 2026 (TRES): a job is GPU if it requested a GPU (--gres), on any
-- partition, superChip included; every other job that ran is CPU.
-- Before 9 May 2026: classified by partition, since TRESReq_gres_gpu is empty
-- before February 2026.
-- Always excluded: staff partitions (deus, purge, secret, secret-gpu), nano by
-- reporting convention, and unresolved multi-partition requests (a value
-- containing '_': the job never started, and Slurm recorded the list it asked
-- for).
-- Before 9 May 2026, any superChip* partition and the retired ait are GPU.
-- 'unclassified' is a partition no rule covers. It is kept visible on purpose,
-- so a new or forgotten partition shows up in answers instead of being
-- silently miscounted. Five retired partitions are left unclassified by
-- decision: graphical, aws, awscpu, awsgpu, uber (2,406 jobs, all before the
-- cutover).
--
-- The cutover is the literal epoch 1778299200 (2026-05-09 00:00 EDT), not
-- UNIX_TIMESTAMP('2026-05-09'), which depends on the session's time zone.
-- TRESReq_gres_gpu is text: empty, NULL and '0' all mean no GPU requested.
-- SELECT r.* is expanded when the view is created: if runTBL2 gains columns,
-- re-run this file to include them.

-- SQL SECURITY INVOKER: the view reads with the caller's own rights, so it
-- grants nothing extra and does not depend on the creating account existing.
CREATE OR REPLACE SQL SECURITY INVOKER VIEW runTBL2_workload AS
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
  END AS workload
FROM runTBL2 r;
