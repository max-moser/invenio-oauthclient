# SPDX-FileCopyrightText: 2016-2018 CERN.
# SPDX-License-Identifier: MIT

"""Test example app."""

import os
import signal
import subprocess
import time
from contextlib import contextmanager

import pytest


@contextmanager
def _create_example_app(app_name):
    """Example app fixture."""
    current_dir = os.getcwd()
    # go to example directory
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    exampleappdir = os.path.join(project_dir, "examples")
    os.chdir(exampleappdir)
    # setup example
    cmd = f"FLASK_APP={app_name} ./app-setup.sh"
    exit_status = subprocess.call(cmd, shell=True)
    assert exit_status == 0
    # Starting example web app
    cmd = f"FLASK_APP={app_name} flask run --debugger -p 5000"
    webapp = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, preexec_fn=os.setsid, shell=True
    )
    time.sleep(5)
    # return webapp
    yield webapp
    # stop server
    os.killpg(webapp.pid, signal.SIGTERM)
    # tear down example app
    cmd = f"FLASK_APP={app_name} ./app-teardown.sh"
    subprocess.call(cmd, shell=True)
    # return to the original directory
    os.chdir(current_dir)
    time.sleep(2)


@pytest.mark.skip(reason="Caused by mergepoint")
@pytest.mark.parametrize("service", ["orcid", "github", "globus"])
def test_app(service):
    """Test example app for given service."""
    with _create_example_app(f"{service}_app.py"):
        cmd = f"curl http://localhost:5000/{service}"
        output = subprocess.check_output(cmd, shell=True).decode("utf-8")
        assert "Redirect" in output


@pytest.mark.skip(reason="Caused by mergepoint")
@pytest.mark.parametrize("service", ["orcid", "github", "globus"])
def test_app_rest(service):
    """Test example app for given service."""
    with _create_example_app(f"{service}_app_rest.py"):
        cmd = f"curl http://localhost:5000/{service}"
        output = subprocess.check_output(cmd, shell=True).decode("utf-8")
        assert "Redirect" in output
