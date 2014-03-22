#!/usr/bin/env python

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
