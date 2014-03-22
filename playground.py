#!/usr/bin/env python
#
# Copyright (c) 2014 Alexander Schrijver <alex@flupzor.nl>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

from sqlalchemy import create_engine, Column, Integer, String, Table, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship

from probescan_wrapper import ProbeFrame

Base = declarative_base()

class ServiceSet(Base):
    __tablename__ = 'servicesets'

    id = Column(Integer, primary_key=True)
    nwid = Column(String, unique=True)

node_serviceset_table = Table('node_serviceset', Base.metadata,
    Column('serviceset_id', Integer, ForeignKey('servicesets.id')),
    Column('node_id', Integer, ForeignKey('nodes.id')),
)

class Node(Base):
    __tablename__ = 'nodes'

    id = Column(Integer, primary_key=True)
    addr = Column(String, unique=True)

    servicesets = relationship("ServiceSet", secondary=node_serviceset_table)

def main():

    engine = create_engine('sqlite:///test.db', echo=False)

    Base.metadata.create_all(engine)

    Session = sessionmaker(bind=engine)

    session = Session()

    for probeframe in ProbeFrame.scan("/home/alex/dump-20-feb-2014-3.pcap"):

        node = session.query(Node).filter_by(addr=probeframe.addr2).first()
        if not node:
            node = Node(addr=probeframe.addr2)
            session.add(node)

        service_set = session.query(ServiceSet).filter_by(nwid=probeframe.nwid).first()

        if not service_set:
            service_set = ServiceSet(nwid=probeframe.nwid)
            session.add(service_set)

        if not service_set in node.servicesets:
            node.servicesets.append(service_set)

        session.commit()


if __name__ == '__main__':
    main()
