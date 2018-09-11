# Copyright (c) 2015 Rackspace, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Taskflow's Flow to update a certificate status.

The flow has below tasks:
    - Check the certificate status
    - Update the certificate status

The flow is LinearFlow and all the tasks are run in a single thread.
"""
from oslo_config import cfg
from taskflow import engines
from taskflow.patterns import linear_flow

from oslo_log import log
from poppy.provider.akamai.background_jobs.check_cert_status_and_update import \
    check_cert_status_and_update_tasks


LOG = log.getLogger(__name__)


conf = cfg.CONF
conf(project='poppy', prog='poppy', args=[])


def check_cert_status_and_update_flow():
    """Create flow to check and update certificate status.

    :return: Linear Flow with check and update tasks
    :rtype: taskflow.patterns.linear_flow.Flow
    """
    flow = linear_flow.Flow('Update Akamai Property').add(
        check_cert_status_and_update_tasks.CheckCertStatusTask(),
        check_cert_status_and_update_tasks.UpdateCertStatusTask()
    )
    return flow


def run_check_cert_status_and_update_flow(domain_name, cert_type, flavor_id,
                                          project_id):
    """Load and Run the ``check_cert_status_and_update_flow`` using Taskflow engine.

    For details about the flow that gets run
    by the engine, refer to :meth:`check_cert_status_and_update_flow()`.

    All the tasks chained in this flow, will run in single thread.

    :param unicode domain_name: The domain name
    :param unicode cert_type: Type of the certificate
    :param unicode flavor_id: Id of the flavor
    :param unicode project_id: The project Id
    """
    e = engines.load(
        check_cert_status_and_update_flow(),
        store={
            'domain_name': domain_name,
            'cert_type': cert_type,
            'flavor_id': flavor_id,
            'project_id': project_id
        },
        engine='serial')
    e.run()
