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
@pytest.fixture(params=SERIES, scope="module")
def series(request):
    return request.param


@pytest.fixture(params=PRINCIPALS, scope="module")
def principal_name(request):
    return request.param


@pytest.fixture(params=SOURCES, ids=[s[0] for s in SOURCES], scope="module")
def source(request):
    return request.param


@pytest.fixture()
async def app(model, series):
    """
    This fixture tries to get and return the application object if it exists.
    """
    application_name='{}-{}'.format("duplicity", series)
    return model.applications.get(application_name)


@pytest.fixture(autouse=True)
async def principal_app(model, principal_name, series):
    # deploy principal app
    application_name = '{}-{}'.format(principal_name, series)
    principal = model.applications.get(application_name)
    if not principal:
        principal = await model.deploy(principal_name,
                              application_name=application_name,
                              series=series)
        #units = principal.units
    return principal


async def test_deploy_duplicity_application(model, source, series, principal_app):
    """
    Test function that verifies successful deployment of the duplicity
    application to the juju model.
    """
    if series != "cosmic":
        await model.block_until(lambda: principal_app.status == 'active',
                            timeout=300)
    # unfortunately juju lib doesnt like to create subordinates, using sp
    application_name = '{}-{}'.format("duplicity", series)
    cmd = ['juju', 'deploy', source[1], '-m', model.info.name,
               '--series', series, application_name]
    subprocess.check_call(cmd)

    print(model.applications)
    #TOFIX
    assert model.applications.get(application_name)

    app = model.applications.get(application_name)
    await model.block_until(lambda: app.status in ['waiting', 'active'])


async def test_deploy_duplicity_unit(model, principal_app, app):
    """ Test function that verifies successful deployment of duplicity
    unit to the model by adding charm relations between a principal
    application, and the duplicity charm as a subordinate.
    """
    await principal_app.add_relation("juju-info", app.name)
    # TODO: verify the relation exists

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


async def test_duplicity_status(model, app):
    # Verifies status for all deployed series of the charm
    await model.block_until(lambda: app.status == 'active')
    unit = app.units[0]
    await model.block_until(lambda: unit.agent_status == 'idle')


async def test_show_history_action(app):
    unit = app.units[0]
    action = await unit.run_action('show-history')
    action = await action.wait()
    assert action.status == 'completed'


async def test_execute_duplicity(app, jujutools):
    """ This test runs a call to the duplicity tool to  ensure that it has been
     installed.
    """
    unit = app.units[0]
    cmd = 'duplicity --version'
    results = await jujutools.run_command(cmd, unit)
    #TOFIX: Thus appears to be using the standard out to validate, not ret code
    assert results['Code'] == '0'
    assert unit.public_address in results['Stdout']


async def test_file_stat(app, jujutools):
    unit = app.units[0]
    path = '/var/lib/juju/agents/unit-{}/charm/metadata.yaml'.format(unit.entity_id.replace('/', '-'))
    fstat = await jujutools.file_stat(path, unit)
    assert stat.filemode(fstat.st_mode) == '-rw-r--r--'
    assert fstat.st_uid == 0
    assert fstat.st_gid == 0
