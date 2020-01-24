#!/usr/bin/env python3

import json
import subprocess

from ops.charm import CharmBase
from ops.framework import StoredState, Object
from ops.main import main
from ops.model import ActiveStatus


class KineCharm(CharmBase):
    state = StoredState()

    def __init__(self, framework, parent):
        super().__init__(framework, parent)

        framework.observe(self.on.install, self)
        framework.observe(self.on.upgrade_charm, self)
        framework.observe(self.on.db_relation_changed, self)
        framework.observe(self.on.certificates_relation_joined, self)
        framework.observe(self.on.certificates_relation_changed, self)
        framework.observe(self.on.cluster_relation_joined, self)
        framework.observe(self.on.cluster_relation_changed, self)

        self.etcd = EtcdProvides(self, "db")
        self.tls = TlsRequires(self, "certificates")

    def on_install(self, event):
        if not hasattr(self.state, 'peers'):
            self.state.peers = [self.get_peer_identity('0.0.0.0')]
        if not hasattr(self.state, 'endpoint'):
            self.state.endpoint = None
        subprocess.run(["snap", "install", "kine", "--edge"])
        subprocess.run(["snap", "refresh", "kine", "--edge"])
        self.on_config_changed(event)

    def on_upgrade_charm(self, event):
        self.on_install(event)
        relation = self.framework.model.get_relation('cluster')
        if relation:
            event.relation = relation
            self.on_cluster_relation_joined(event)
            self.on_cluster_relation_changed(event)

    def on_config_changed(self, event):
        endpoint = self.get_dqlite_endpoint()
        if endpoint != self.state.endpoint:
            self.state.endpoint = endpoint
            subprocess.run(["snap", "set", "kine", f"endpoint={endpoint}",
                            f"dqlite-id={self.get_unit_id()}"])
            subprocess.run(["snap", "restart", "kine"])
        self.framework.model.unit.status = ActiveStatus()

    def on_db_relation_changed(self, event):
        ip = event.relation.data[self.framework.model.unit]['ingress-address']
        self.etcd.set_connection_string(f"http://{ip}:2379")

    def on_certificates_relation_joined(self, event):
        self.tls.request_client_cert('cn', [])

    def on_certificates_relation_changed(self, event):
        if not all([self.tls.root_ca_cert, self.tls.client_certs]):
            return

        key = self.tls.client_certs['key']
        cert = self.tls.client_certs['cert']
        ca = self.tls.root_ca_cert
        self.etcd.set_client_credentials(key, cert, ca)

    def on_cluster_relation_joined(self, event):
        unit = self.framework.model.unit
        my_address = event.relation.data[self.framework.model.unit]['ingress-address']
        self.state.my_identity = self.get_peer_identity(my_address)
        event.relation.data[unit]['peer_identity'] = self.state.my_identity

    def on_cluster_relation_changed(self, event):
        self.state.peers = [self.get_peer_identity('0.0.0.0')]
        for unit in event.relation.units:
            if 'peer_identity' not in event.relation.data[unit]:
                continue
            self.state.peers.append(event.relation.data[unit]['peer_identity'])
        self.on_config_changed(event)

    def get_unit_id(self):
        unit = self.framework.model.unit
        unit_num = (int(unit.name.split('/')[1]) % 9) + 1
        return unit_num

    def get_peer_identity(self, address):
        id_ = self.get_unit_id()
        return f"{id_}:{address}:918{id_}"

    def get_dqlite_endpoint(self):
        """Get dqlite connection string, e.g.: dqlite://?peer=1:127.0.0.1:9187

        """
        prefix = "dqlite://?peer="
        peers = '&peer='.join(self.state.peers)
        return prefix + peers


class EtcdProvides(Object):
    def __init__(self, parent, key):
        super().__init__(parent, key)
        self.name = key

    def set_client_credentials(self, key, cert, ca):
        ''' Set the client credentials on the global conversation for this
        relation. '''
        unit = self.framework.model.unit
        for relation in self.framework.model.relations[self.name]:
            relation.data[unit]['client_key'] = key
            relation.data[unit]['client_cert'] = cert
            relation.data[unit]['client_ca'] = ca

    def set_connection_string(self, connection_string, version='3.'):
        ''' Set the connection string on the global conversation for this
        relation. '''
        unit = self.framework.model.unit
        for relation in self.framework.model.relations[self.name]:
            relation.data[unit]['connection_string'] = connection_string
            relation.data[unit]['version'] = version


class TlsRequires(Object):
    def __init__(self, parent, key):
        super().__init__(parent, key)
        self.name = key

    def request_client_cert(self, cn, sans):
        """
        Request a client certificate and key be generated for the given
        common name (`cn`) and list of alternative names (`sans`).

        This can be called multiple times to request more than one client
        certificate, although the common names must be unique.  If called
        again with the same common name, it will be ignored.
        """
        relations = self.framework.model.relations[self.name]
        if not relations:
            return
        # assume we'll only be connected to one provider
        relation = relations[0]
        unit = self.framework.model.unit
        requests = relation.data[unit].get('client_cert_requests', '{}')
        requests = json.loads(requests)
        requests[cn] = {'sans': sans}
        relation.data[unit]['client_cert_requests'] = json.dumps(requests, sort_keys=True)

    @property
    def root_ca_cert(self):
        """
        Root CA certificate.
        """
        # only the leader of the provider should set the CA, or all units
        # had better agree
        for relation in self.framework.model.relations[self.name]:
            for unit in relation.units:
                if relation.data[unit].get('ca'):
                    return relation.data[unit].get('ca')

    @property
    def client_certs(self):
        """
        List of [Certificate][] instances for all available client certs.
        """
        unit_name = self.framework.model.unit.name.replace('/', '_')
        field = '{}.processed_client_requests'.format(unit_name)

        for relation in self.framework.model.relations[self.name]:
            for unit in relation.units:
                if field not in relation.data[unit]:
                    continue
                certs_data = relation.data[unit][field]
                if not certs_data:
                    continue
                certs_data = json.loads(certs_data)
                if not certs_data:
                    continue
                return list(certs_data.values())[0]


if __name__ == '__main__':
    main(KineCharm)
