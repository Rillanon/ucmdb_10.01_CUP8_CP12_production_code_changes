#coding=utf-8
from appilog.common.system.types.vectors import ObjectStateHolderVector
from appilog.common.system.types import ObjectStateHolder
import Util
import Queries

import logger
import modeling

class SqlDatabase:
    def __init__(self, connection, discoveryOptions):
        self.connection = connection
        self.discoveryOptions = discoveryOptions

    def collectData(self,dbName,db,hostId,users):
        oshv = ObjectStateHolderVector()
        try:
            self.connection.setWorkingDatabase(dbName)
            if self.discoveryOptions and self.discoveryOptions.discoverSqlFile:
                self.getSqlFiles(oshv,dbName,db,hostId)
            self.attachToUsers(db,users,oshv)
        except:
            logger.debugException('failed to get DB configuration: ', dbName)
        return oshv

    def attachToUsers(self,db,users,oshv):
        rs = self.connection.getTable(Queries.DATABASE_USERS)
        while(rs.next()):
            name = rs.getString('name')
            user = users.get(name)
            if(user is not None):
                owner = modeling.createLinkOSH('owner', user, db)
                oshv.add(owner)
        rs.close()

    def getSqlFiles(self,oshv,dbName,db,hostId):
        query = Util.replaceAll(Queries.DATABASE_FILES,dbName)
        rs = self.connection.getTable(query)
        while rs.next():
            path = Util.replaceFileSeparator(rs.getString('filename'))
            fileName = rs.getString('name').strip()
            size = self.normalizeSize(rs.getString('size'))
            growth = self.normalizeSize(rs.getString('growth'))
            max = self.normalizeSize(rs.getString('maxsize'))
            if(max=='-1'):
                max = 'unlimited'
            osh = ObjectStateHolder('sqlfile')
            osh.setAttribute(Queries.DATA_NAME,fileName)
            osh.setAttribute('sqlfile_path',path)
            osh.setAttribute('sqlfile_size',size)
            osh.setAttribute('sqlfile_size_double',float(size)) # added by Daniel La because sqlfile_size is represented as a string. Can't use for calculations 10/01/2012
            osh.setAttribute('sqlfile_growth',growth)
            osh.setContainer(db)
            oshv.add(osh)
            disk = Util.getDisk(path,hostId)
            oshv.add(disk)
            oshv.add(modeling.createLinkOSH('depend', osh, disk))
        rs.close()

    def normalizeSize(self,size):
        isize = int(size)
        if(size==-1 or size <=100):
            return size
        return str(isize/128)
