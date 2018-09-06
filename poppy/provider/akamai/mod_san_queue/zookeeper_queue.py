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
from poppy.provider.akamai.mod_san_queue import base
from poppy.provider.akamai import utils


AKAMAI_OPTIONS = [
    # queue backend configs
    cfg.StrOpt(
        'queue_backend_type',
        help='SAN Cert Queueing backend'),
    cfg.ListOpt('queue_backend_host', default=['localhost'],
                help='default queue backend server hosts'),
    cfg.IntOpt('queue_backend_port', default=2181, help='default'
               ' default queue backend server port (e.g: 2181)'),
    cfg.StrOpt(
        'mod_san_queue_path', default='/mod_san_queue', help='Zookeeper path '
        'for mod_san_queue'),
]

AKAMAI_GROUP = 'drivers:provider:akamai:queue'


class ZookeeperModSanQueue(base.ModSanQueue):
    """Buffer Mod San requests.

    We have configured list of SAN certificate names
    in ``poppy.conf``. Whenever a request to add a
    domain comes, One of SAN certificate will be choosen
    from the list to add the domain; making that SAN
    cert status ``pending`` for some time. In such
    scenario where there is no ``Available`` certificate
    present from the list and if a new request comes to add
    another domain, then that request will be stored in
    this ``mod san queue`` for future processing.

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
        super(ZookeeperModSanQueue, self).__init__(conf)

        self._conf.register_opts(AKAMAI_OPTIONS,
                                 group=AKAMAI_GROUP)
        self.akamai_conf = self._conf[AKAMAI_GROUP]

    @decorators.lazy_property(write=False)
    def mod_san_queue_backend(self):
        """Return Zookeeper locking queue.

        :return: Locking queue object
        :rtype: kazoo.recipe.queue.LockingQueue
        """
        return queue.LockingQueue(
            self.zk_client,
            self.akamai_conf.mod_san_queue_path)

    @decorators.lazy_property(write=False)
    def zk_client(self):
        """Create and Return zookeeper client.

        :return: Zookeeper client
        :rtype: kazoo.client.KazooClient
        """
        return utils.connect_to_zookeeper_queue_backend(self.akamai_conf)

    def enqueue_mod_san_request(self, cert_obj_json):
        """Put certificate details into queue.

        Example input ``cert_obj_json``. (Serialize
        the dict and use it as an input to store the
        certificate details into the queue.)

        .. code-block:: python

            '{
                "cert_type": "san",
                "domain_name": "www.abc.com",
                "flavor_id": "premium"
            }'

        :param str cert_obj_json: Serialized dictionary
            with certificate details
        """
        self.mod_san_queue_backend.put(cert_obj_json)

    def traverse_queue(self):
        """Get list of all items in the queue.

        Even though the queue is emptied while traversing,
        all the items will be put back into queue. So, the
        queue will be intact after the traversal.

        :return: List of certificates in the queue
        :rtype: list[str]
        """
        res = []
        while len(self.mod_san_queue_backend) > 0:
            item = self.mod_san_queue_backend.get()
            self.mod_san_queue_backend.consume()
            res.append(item)
        self.mod_san_queue_backend.put_all(res)
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
        while len(self.mod_san_queue_backend) > 0:
            self.mod_san_queue_backend.get()
            self.mod_san_queue_backend.consume()
        # put in all the new data
        self.mod_san_queue_backend.put_all(queue_data)
        return queue_data

    def dequeue_mod_san_request(self, consume=True):
        """Returns entry from the queue.

        Example return.

        .. code-block:: python

            '{
                "cert_type": "san",
                "domain_name": "www.abc.com",
                "flavor_id": "premium"
            }'

        :param bool consume: (Default True) If set to
            ``True``, the entry from the queue will be
            deleted. Else, entry will be returned only.

        :return: Serialized dictionary
            with certificate details
        :rtype: str
        """
        res = self.mod_san_queue_backend.get()
        if consume:
            self.mod_san_queue_backend.consume()
        return res
