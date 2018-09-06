# Copyright (c) 2014 Rackspace, Inc.
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
from poppy.provider.akamai.domain_san_mapping_queue import base
from poppy.provider.akamai import utils


AKAMAI_OPTIONS = [
    # queue backend configs
    cfg.StrOpt(
        'queue_backend_type',
        help='SAN Cert Queueing backend'),
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
        'san_mapping_queue_path',
        default='/san_mapping_queue',
        help='Zookeeper path '
        'for san_mapping_queue'
    ),
]

AKAMAI_GROUP = 'drivers:provider:akamai:queue'


class ZookeeperSanMappingQueue(base.SanMappingQueue):
    """Store ``domain to san cert`` mappings.

    Once a domain name is added to san cert, the mapping
    of domain to san cert will be stored in this queue.

    A background job that runs at pre-defined intervals
    will process this queue and will trigger task that
    uses these mappings to update the Akamai configuration.

    The queue is implemented using ``zookeeper`` and
    is a ``locking queue``.

    The path for the queue is read from the section
    ``drivers:provider:akamai:queue]`` in ``poppy.conf``
    """

    def __init__(self, conf):
        """Initialize Zookeeper locking queue.

         :param conf: Poppy configuration
         :type conf: oslo_config.ConfigOpts
        """
        super(ZookeeperSanMappingQueue, self).__init__(conf)

        self._conf.register_opts(AKAMAI_OPTIONS,
                                 group=AKAMAI_GROUP)
        self.akamai_conf = self._conf[AKAMAI_GROUP]

    @decorators.lazy_property(write=False)
    def san_mapping_queue_backend(self):
        """Return Zookeeper locking queue.

        :return: Locking queue object
        :rtype: kazoo.recipe.queue.LockingQueue
        """
        return queue.LockingQueue(
            self.zk_client,
            self.akamai_conf.san_mapping_queue_path)

    @decorators.lazy_property(write=False)
    def zk_client(self):
        """Create and Return zookeeper client.

        :return: Zookeeper client
        :rtype: kazoo.client.KazooClient
        """
        return utils.connect_to_zookeeper_queue_backend(self.akamai_conf)

    def enqueue_san_mapping(self, san_domain_map):
        """Put mapping details into queue.

        Example input ``san_domain_map``. (Serialize
        the dict and use it as an input to store the
        mapping details into the queue.)

        .. code-block:: python

           '{
                "domain_name": "test-san1.cnamecdn.com",
                "flavor_id": "premium",
                "project_id": "003",
                "cert_type": "san",
                "cert_details": {
                    "Akamai": {
                        "extra_info": {
                            "san cert": "san1.example.com",
                            "akamai_spsId": 1
                        }
                    }
                }
            }'

        :param str san_domain_map: Serialized dictionary
            with mapping details
        """
        self.san_mapping_queue_backend.put(san_domain_map)

    def traverse_queue(self, consume=False):
        """Get list of all items in the queue.

        :param bool consume: (Default False) If set to
        ``True``, the queue will be emptied. Otherwise,
        queue will be intact.

        :return: List of mapping in the queue
        :rtype: list[str]
        """
        res = []
        while len(self.san_mapping_queue_backend) > 0:
            item = self.san_mapping_queue_backend.get()
            self.san_mapping_queue_backend.consume()
            res.append(item)
        if consume is False:
            self.san_mapping_queue_backend.put_all(res)
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
        while len(self.san_mapping_queue_backend) > 0:
            self.san_mapping_queue_backend.get()
            self.san_mapping_queue_backend.consume()
        # put in all the new data
        self.san_mapping_queue_backend.put_all(queue_data)
        return queue_data

    def dequeue_san_mapping(self, consume=True):
        """Returns entry from the queue.

        Example return.

        .. code-block:: python

            '{
                "domain_name": "test-san1.cnamecdn.com",
                "flavor_id": "premium",
                "project_id": "003",
                "cert_type": "san",
                "cert_details": {
                    "Akamai": {
                        "extra_info": {
                            "san cert": "san1.example.com",
                            "akamai_spsId": 1
                        }
                    }
                }
            }'

        :param bool consume: (Default True) If set to
            ``True``, the entry from the queue will be
            deleted. Else, only entry will be returned.

        :return: Serialized dictionary
            with mapping details
        :rtype: str
        """
        res = self.san_mapping_queue_backend.get()
        if consume:
            self.san_mapping_queue_backend.consume()
        return res
