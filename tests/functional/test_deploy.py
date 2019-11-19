import os
import pytest
import subprocess
import stat
import asyncio

# Treat all tests as coroutines
pytestmark = pytest.mark.asyncio

JUJU_REPO = os.getenv('JUJU_REPOSITORY', '.').rstrip('/')
SERIES = ['xenial',
          'bionic',
          pytest.param('cosmic', marks=pytest.mark.xfail(reason=\
                                            'Charm version not supported')),
          ]
SOURCES = [('local', '{}/builds/duplicity'.format(JUJU_REPO)),
           # ('jujucharms', 'cs:...'),
           ]
PRINCIPALS = ['ubuntu',
              'grafana']


# Custom fixtures
# Parameterized fixtures
@pytest.fixture(params=SERIES, scope="function")
def series(request):
    return request.param


@pytest.fixture(params=PRINCIPALS, scope="module")
def principal_name(request):
    return request.param


@pytest.fixture(params=SOURCES, ids=[s[0] for s in SOURCES], scope="module")
def source(request):
    return request.param

# Setup Test Models
@pytest.fixture()
async def app(model, series, source):
    """
    This fixture tries to get and return the application object if it exists.
    """
    application_name='{}-{}-{}'.format("duplicity", series, source[0])
    return model.applications.get(application_name)


@pytest.fixture(scope="module", autouse=True)
async def deploy_backup_host(model):
    """
    This is an autouse fixture which initiates non-blocking creation of a
    backup host to be used during testing.
    """
    application_name = "backup-test-host"
    if not model.applications.get(application_name):
        await model.deploy("ubuntu",
                       application_name=application_name,
                       series="bionic")


@pytest.fixture()
async def backup_host(model):
    """ Gets and returns lib juju application object for the backup host """
    application_name = "backup-test-host"
    # TODO This should wait until host deployment is complete
    return model.applications.get(application_name)


@pytest.fixture(scope="module", autouse=True)
async def deploy_all_principals(model):
    """ This is an autouse fixture that tries to pre-empt creation of all
    principal applications so tests will run slightly faster """
    for series in SERIES:
        if not isinstance(series, str):
            # Skip the non str param, its a pytest.mark obj
            continue
        for principal_name in PRINCIPALS:
            application_name = '{}-{}'.format(principal_name, series)
            principal = model.applications.get(application_name)
            if not principal:
                await model.deploy(principal_name,
                          application_name=application_name,
                          series=series)


@pytest.fixture()
async def principal_app(model, principal_name, series):
    """ Fixture to retrieve the the deployed principal application """
    application_name = '{}-{}'.format(principal_name, series)
    return model.applications.get(application_name)


@pytest.mark.skipif(os.getenv("PYTEST_MODEL") is not None and
               os.getenv ("PYTEST_KEEP_MODEL") is not None and
               os.getenv("PYTEST_KEEP_MODEL").lower() == 'true',
               reason="Applications are already deployed.")
async def test_deploy_duplicity_application(model, source, series):
    """
    Test function that verifies successful deployment of the duplicity
    application to the juju model.
    """
    # unfortunately juju lib doesnt like to create subordinates, using sp
    application_name = '{}-{}-{}'.format("duplicity", series, source[0])
    cmd = ['juju', 'deploy', source[1], '-m', model.info.name,
               '--series', series, application_name]
    subprocess.check_call(cmd)
    await asyncio.sleep(3)
    assert model.applications.get(application_name)
    app = model.applications.get(application_name)
    await model.block_until(lambda: app.status in ['waiting', 'active'])


async def test_deploy_duplicity_unit(model, principal_app, app):
    """ Test function that verifies successful deployment of duplicity
    unit to the model by adding charm relations between a principal
    application, and the duplicity charm as a subordinate.
    """
    relation = "{}:general-info {}:juju-info".format(app.name,
                                                     principal_app.name)
    if list(filter( lambda x: x.key == relation, app.relations)):
        pytest.skip("Relation {} already exists.".format(relation))
    else:
        await principal_app.add_relation("juju-info", app.name)
    rel = filter(lambda rel: rel.key == relation, app.relations)
    assert rel


async def test_charm_upgrade(model, app):
    if app.name.endswith('local'):
        pytest.skip("No need to upgrade the local deploy")
    unit = app.units[0]
    await model.block_until(lambda: unit.agent_status == 'idle')
    subprocess.check_call(['juju',
                           'upgrade-charm',
                           '--switch={}'.format(SOURCES[0][1]),
                           '-m', model.info.name,
                           app.name,
                           ])
    await model.block_until(lambda: unit.agent_status == 'executing')


async def test_duplicity_status(model, app,):
    # Verifies status for all deployed series of the charm
    await model.block_until(lambda: app.status == 'active')
    unit = app.units[0]
    await model.block_until(lambda: unit.agent_status == 'idle')


async def test_verify_action(app):
    unit = app.units[0]
    action = await unit.run_action('verify')
    action = await action.wait()
    assert action.status == 'completed'


async def test_execute_duplicity(app, jujutools):
    """ This test runs a call to the duplicity tool to  ensure that it has been
     installed.
    """
    unit = app.units[0]
    cmd = 'duplicity --version'
    results = await jujutools.run_command(cmd, unit)
    assert results['Code'] == '0'


async def test_file_stat(app, jujutools):
    unit = app.units[0]
    path = '/var/lib/juju/agents/unit-{}/charm/metadata.yaml'.format(unit.entity_id.replace('/', '-'))
    fstat = await jujutools.file_stat(path, unit)
    assert stat.filemode(fstat.st_mode) == '-rw-r--r--'
    assert fstat.st_uid == 0
    assert fstat.st_gid == 0
