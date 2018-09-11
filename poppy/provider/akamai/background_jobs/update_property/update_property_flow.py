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

"""Taskflow's Flow to update and activate property.

The flow has below tasks:
    - Get latest property version
    - Update the latest property
    - Activate the latest property
    - Update ``san mapping`` queue with activated properties

The flow is LinearFlow and all the tasks are run in a single thread.
"""
from oslo_config import cfg
from taskflow import engines
from taskflow.patterns import linear_flow

from oslo_log import log
from poppy.provider.akamai.background_jobs.update_property import (
    update_property_tasks)


LOG = log.getLogger(__name__)


conf = cfg.CONF
conf(project='poppy', prog='poppy', args=[])


def update_property_flow():
    """Constructs the LinearFlow of independent tasks.

    :return: A Linear Flow of property tasks
    :rtype: taskflow.patterns.linear_flow.Flow
    """
    flow = linear_flow.Flow('Update Akamai Property').add(
        update_property_tasks.PropertyGetLatestVersionTask(),
        update_property_tasks.PropertyUpdateTask(),
        update_property_tasks.PropertyActivateTask(),
        update_property_tasks.MarkQueueItemsWithActivatedProperty()
    )
    return flow


def run_update_property_flow(property_spec, update_type, update_info_list):
    """Load and Run the ``update_property_flow`` using Taskflow engine.

    For details about the flow that gets run
    by the engine, refer to :meth:`update_property_flow()`.

    All the tasks chained in this flow, will run in single thread.

    :param unicode property_spec: The property name
    :param str update_type: Type of the update
    :param list update_info_list: List of tuples with action and
      cname host mapping info
    """
    e = engines.load(
        update_property_flow(),
        store={
            "property_spec": property_spec,
            "update_type": update_type,
            "update_info_list": update_info_list
        },
        engine='serial')
    e.run()
