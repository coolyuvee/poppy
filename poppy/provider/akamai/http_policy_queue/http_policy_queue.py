# Copyright (c) 2016 Rackspace, Inc.
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

from kazoo.recipe import queue
from oslo_config import cfg

from poppy.common import decorators
from poppy.provider.akamai.http_policy_queue import base
from poppy.provider.akamai import utils


AKAMAI_OPTIONS = [
    # queue backend configs
    # cfg.StrOpt(
    #     'queue_backend_type',
    #     help='HTTP policy queueing backend'),
    cfg.ListOpt(
        'queue_backend_host',
        default=['localhost'],
        help='default queue backend server hosts'),
    cfg.IntOpt(
        'queue_backend_port',
        default=2181,
        help='default'
        ' default queue backend server port (e.g: 2181)'),
    cfg.StrOpt(
        'http_policy_queue_path',
        default='/http_policy_queue',
        help='Zookeeper path '
        'for http_policy_queue'
    ),
]

AKAMAI_GROUP = 'drivers:provider:akamai:queue'


class ZookeeperHttpPolicyQueue(base.HttpPolicyQueue):
    """Queue to store old HTTP policies.

    Store the obsolete HTTP policies to mark them
    for deletion; below are the scenarios in which
    we mark the policies for the deletion:
        -  Whenever a domain is migrated from http to
           https
        - Updating services

    The queue is implemented using ``zookeeper`` and
    is a ``locking queue``.

    The path for the queue is read from ``poppy.conf``
    """

    def __init__(self, conf):
        """Initialize Zookeeper locking queue.

        :param conf: Poppy configuration
        :type conf: oslo_config.ConfigOpts
        """
        super(ZookeeperHttpPolicyQueue, self).__init__(conf)

        self._conf.register_opts(AKAMAI_OPTIONS,
                                 group=AKAMAI_GROUP)
        self.akamai_conf = self._conf[AKAMAI_GROUP]

    @decorators.lazy_property(write=False)
    def http_policy_queue_backend(self):
        """Return Zookeeper locking queue.

        :return: Locking queue object
        :rtype: kazoo.recipe.queue.LockingQueue
        """

        return queue.LockingQueue(
            self.zk_client,
            self.akamai_conf.http_policy_queue_path)

    @decorators.lazy_property(write=False)
    def zk_client(self):
        """Create and Return zookeeper client.

        :return: Zookeeper client
        :rtype: kazoo.client.KazooClient
        """
        return utils.connect_to_zookeeper_queue_backend(self.akamai_conf)

    def enqueue_http_policy(self, http_policy):
        """Put http policy details into queue.

        Example input ``http_policy``. (Serialize
        the dict and use it as parameter to store
        the policy into queue.)

        .. code-block:: python

            '{
                "configuration_number": 1,
                "policy_name": "www.abc.com",
                "project_id": "12345"
            }'

        :param str http_policy: Serialized dictionary
            with policy details
        """
        self.http_policy_queue_backend.put(http_policy)

    def traverse_queue(self, consume=False):
        """Get list of all items in the queue.

        :param bool consume: (Default False) If set to
        ``True``, the queue will be emptied. Otherwise,
        queue will be intact.

        :return: List of policies in the queue
        :rtype: list[str]
        """
        res = []
        while len(self.http_policy_queue_backend) > 0:
            item = self.http_policy_queue_backend.get()
            self.http_policy_queue_backend.consume()
            res.append(item)
        if consume is False:
            self.http_policy_queue_backend.put_all(res)
        return res

    def put_queue_data(self, queue_data):
        """Replace the Queue with new incoming data.

        All the existing data in the queue will be
        deleted and replaced with the supplied
        ``queue_data``.

        :param list queue_data: The new data to replace
            the queue with.

        :return: New items present in the queue.
        :rtype: list
        """
        while len(self.http_policy_queue_backend) > 0:
            self.http_policy_queue_backend.get()
            self.http_policy_queue_backend.consume()
        # put in all the new data
        self.http_policy_queue_backend.put_all(queue_data)
        return queue_data

    def dequeue_http_policy(self, consume=True):
        """Returns entry from the queue.

        Example return:

        .. code-block:: python

            '{
                "configuration_number": 1,
                "policy_name": "www.abc.com",
                "project_id": "12345"
            }'

        :param bool consume: (Default True) If set to
            ``True``, the entry from the queue will be
            deleted. Else, entry will be returned only.

        :return: Serialized dictionary
            with policy details
        :rtype: str
        """

        res = self.http_policy_queue_backend.get()
        if consume:
            self.http_policy_queue_backend.consume()
        return res
