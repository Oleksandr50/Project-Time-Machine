"""Internal full suite or explicit public suite with private fixture skips reported."""
from pathlib import Path
import argparse,os,sys,unittest
root=Path(__file__).resolve().parents[1];sys.path.insert(0,str(root))
os.environ.setdefault('PTM_TEST_DEPS','')
if os.environ['PTM_TEST_DEPS']:sys.path[1:1]=os.environ['PTM_TEST_DEPS'].split(os.pathsep)
p=argparse.ArgumentParser();p.add_argument('--public',action='store_true');args=p.parse_args()
suite=unittest.defaultTestLoader.discover(str(root/'tests'),pattern='test_*.py')
private={
 'test_stage2.AuthorizationTests.test_stage1_registry_upgrade_preserves_all_project_columns',
 'test_stage6.StageSixMigrationTests.test_stage5_real_database_copies_preserve_all_old_columns_and_ids',
}
def entries(suite):
 for test in suite:
  if isinstance(test,unittest.TestSuite):yield from entries(test)
  else:yield test
if args.public:
 for test in entries(suite):
  if test.id() in private:
   method=getattr(test,test._testMethodName)
   setattr(test,test._testMethodName,unittest.skip('Private historical database fixture is not distributed; internal migration suite is separate')(method))
sys.exit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
