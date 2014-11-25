#coding=utf-8
##################################################################################################################
#
#                   db2_dis_physical - Discovery Pattern for discover DB2 client connection and DB2 tablespace
#
#                   Last Update: 13/05/2013
#                   Last Update By : Daniel La
##################################################################################################################
from modeling import HostBuilder
import string
import sys
import re  # added by Daniel La

import logger
import modeling
import errormessages
import shellutils
 # added by Daniel La

from appilog.common.system.types.vectors import ObjectStateHolderVector
from appilog.common.system.types import ObjectStateHolder
from appilog.common.utils.parser import DateParser
from java.lang import Exception as JavaException
from com.hp.ucmdb.discovery.library.clients import ClientsConsts

# below two added by Daniel La
from java.util import Properties
from com.hp.ucmdb.discovery.library.clients.agents import BaseAgent

# getShellUtils() - added by Daniel La
def getShellUtils(Framework, protocol, shellCredentialsId, protocolProperties):
    ''' Establish connection using specified credentials and get Shell
    @types: Framework, str, str, str, java.util.Properties -> Shell
    @raise Exception: failed to detect OS
    '''
    Props = Properties()
    codePage = Framework.getCodePage()
    Props.setProperty( BaseAgent.ENCODING, codePage)
    Props.setProperty('credentialsId', shellCredentialsId)
    shellUtils = shellutils.ShellUtils(Framework, Props)
    return shellUtils

def validate_ipstring(hostName,db2Client):
    if hostName=="LOCAL" or hostName=="*LOCAL":
        return db2Client.getIpAddress()
    ind=len(hostName)
    if (ind==7):
        hostName='0' + hostName;

#    Note: When the hexadecimal versions of the IP address or port number begin with 0-9,
#    they are changed to G-P respectively.
#    For example, "0" is mapped to "G", "1" is mapped to "H", and so on.

    if hostName[0] > 'F':
        if hostName[0] == 'G':
            hostName = '0' + hostName[1:]
        if hostName[0] == 'H':
            hostName = '1' + hostName[1:]
        if hostName[0] == 'I':
            hostName = '2' + hostName[1:]
        if hostName[0] == 'J':
            hostName = '3' + hostName[1:]
        if hostName[0] == 'K':
            hostName = '4' + hostName[1:]
        if hostName[0] == 'L':
            hostName = '5' + hostName[1:]
        if hostName[0] == 'M':
            hostName = '6' + hostName[1:]
        if hostName[0] == 'N':
            hostName = '7' + hostName[1:]
        if hostName[0] == 'O':
            hostName = '8' + hostName[1:]
        if hostName[0] == 'P':
            hostName = '9' + hostName[1:]


    tmp= str(int(eval('0x'+hostName[0]+hostName[1])))+ '.' + str(int(eval('0x'+hostName[2]+hostName[3])))+'.'+str(
            int(eval('0x'+hostName[4]+hostName[5])))+'.'+str(int(eval('0x'+hostName[6]+hostName[7])))
    hostName=tmp
    return hostName

# this returns the filesystem that the datafile resides on - Daniel La
def getDisk(path,hostId, ostype):
    if (ostype == 'win'):
        diskName = path.split(':\\')[0].upper()
        if (len(diskName) > 1):
            return None
    else:
        diskName = path
    type = modeling.UNKNOWN_STORAGE_TYPE
    return modeling.createDiskOSH(hostId, diskName, type, name = diskName)

#######################################################################
#
# addDBFile - add dbFile in specific DB
# file_name: the file,parnetID: the dbServer process
#
#######################################################################
# def addDBFile(full_path_name,dbtablespace,tblspcname,database_server,file_id,maxsize, OSHVResult):
def addDBFile(full_path_name,dbtablespace,tblspcname,database_server,file_id,maxsize, OSHVResult, shellUtils, hostid):
    dbFileOSH = ObjectStateHolder('dbdatafile')
    dbFileOSH.setAttribute('data_name', full_path_name)
    dbFileOSH.setAttribute('dbdatafile_fileid', file_id)
    dbFileOSH.setAttribute('dbdatafile_tablespacename',tblspcname)
    dbFileOSH.setAttribute('dbdatafile_maxbytes', str(maxsize))
    dbFileOSH.setContainer(database_server)
    OSHVResult.add(dbFileOSH)

    resource=modeling.createLinkOSH('resource', dbtablespace, dbFileOSH)
    OSHVResult.add(resource)

    # added code to work out which filesystem data file sits on and then create link to filesystem - Daniel La
    disk = None
    if (shellUtils != None): # AIX box
        try:
            cmd = 'df \"' + full_path_name + '\" | awk \'NR==1 {next} {print $7; exit}\''
            mountpoint = shellUtils.execCmd(cmd)
            if mountpoint and shellUtils.getLastCmdReturnCode() == 0 and not re.search('Cannot find or open file system', mountpoint):
                ostype = 'unix'
                disk = getDisk(mountpoint.strip(),hostid,ostype)
                if (disk != None):
                    OSHVResult.add(disk)
                    # OSHVResult.add(modeling.createLinkOSH('depend', dbFileOSH, disk)) # ucmdb 8.x - Daniel La
                    OSHVResult.add(modeling.createLinkOSH('usage', dbFileOSH, disk))
            else:
                logger.debug('Failed running: ' + cmd)
        except:
            logger.debugException('Failed running: ' + cmd)
    else: # WIndows box
        ostype = 'win'
        disk = getDisk(full_path_name,hostid,ostype)
        if (disk != None):
            OSHVResult.add(disk)
            # OSHVResult.add(modeling.createLinkOSH('depend', dbFileOSH, disk))   # ucmdb 8.x - Daniel La
            OSHVResult.add(modeling.createLinkOSH('usage', dbFileOSH, disk))


#######################################################################
#
# getDBTablespace - get the all tablespaces
# db_conn: connection,db: name of the DB,parnetID: the dbServer process
#
#######################################################################
# def getDBTablespace(db2Client,parentID,hostid,OSHVResult):
def getDBTablespace(db2Client,parentID,hostid,OSHVResult, shellUtils): # adjusted by Daniel La
    rs = None
    try:
        dbfid = 1
        rs = db2Client.executeQuery("select a.TABLESPACE_NAME,a.CONTAINER_NAME,0,A.TABLESPACE_ID  from TABLE(sysproc.SNAPSHOT_CONTAINER('" + db2Client.getDatabaseName() +"',-2)) as a")#@@CMD_PERMISION sql protocol execution
        while (rs.next()):
            name = string.strip(rs.getString(1))
            phyname = string.strip(rs.getString(2))
            ## Fix for Defect 32863 to enable handling multiple datafiles per tablespace

            # dbfid = rs.getInt(4) + dbfid
            # Daniel La - modified slightly as can have situations where rs.getInt(4) = 0 so end up with duplicates.
            dbfid = rs.getInt(4) + dbfid + 1


            dbtblspOSH = ObjectStateHolder('dbtablespace')
            dbtblspOSH.setAttribute('data_name', name)
            dbtblspOSH.setContainer(parentID)
            OSHVResult.add(dbtblspOSH)
            if (phyname!=''):
                # addDBFile(phyname,dbtblspOSH,name,parentID,dbfid,0, OSHVResult)
                addDBFile(phyname,dbtblspOSH,name,parentID,dbfid,0, OSHVResult, shellUtils,hostid) # adjusted by Daniel La
    finally:
        if rs != None:
            rs.close()


#######################################################################
#
# getDBSession - get the all client connected to this db
#
#######################################################################
def getDBSession(db2Client, parentID, OSHVResult):
    rs = None
    try:
        rs = db2Client.executeQuery("select appl_name,substr(appl_id,1,posstr(appl_id,'.')-1),AUTH_ID,CLIENT_NNAME,client_pid,count(*) from TABLE(sysproc.SNAPSHOT_APPL_INFO('"+ db2Client.getDatabaseName() + "',-2)) as a group by  appl_name,substr(appl_id,1,posstr(appl_id,'.')-1),AUTH_ID,CLIENT_NNAME,client_pid")#@@CMD_PERMISION sql protocol execution
        while rs.next():
            programName = string.strip(rs.getString(1))
            hostName = string.strip(rs.getString(2))
            user = string.strip(rs.getString(3))
#            pid = rs.getInt(5)
            connection_count = rs.getInt(6)
            hostIp = ''
            try:
                hostIp = validate_ipstring(hostName, db2Client)
            except:
                logger.warn('Received invalid hostName: %s' % hostName)
                continue

            if programName:
                processName = programName
            else:
                processName = str(user) + '@' + str(hostName)

            # Filter processes named 'db2jcc_application' since this is default name
            # given by DB2 when the process name is unknown
            if processName == 'db2jcc_application':
                continue

            if hostIp:
                procHostOSH = modeling.createHostOSH(hostIp)
                OSHVResult.add(procHostOSH)

            if procHostOSH:
                processOSH = modeling.createProcessOSH(processName, procHostOSH, processName, None, None, None, user)
                OSHVResult.add(processOSH)

                dbLink = modeling.createLinkOSH('dbclient', parentID, processOSH)
                dbLink.setAttribute('dbclient_connectioncount', connection_count)
                OSHVResult.add(dbLink)
    finally:
        rs and rs.close()

def getDBSchemas(db2Client,parentID,OSHVResult):
    rs = None
    try:
        rs = db2Client.executeQuery("select SCHEMANAME, CREATE_TIME from SYSCAT.SCHEMATA")#@@CMD_PERMISION sql protocol execution
        while (rs.next()):
            schemaOSH = ObjectStateHolder('db2_schema')
            schemaOSH.setAttribute('data_name', rs.getString(1))
            schemaOSH.setAttribute("createdate", DateParser.parse(rs.getTimestamp(2)))
            schemaOSH.setContainer(parentID)
            OSHVResult.add(schemaOSH)
    finally:
        if rs != None:
            rs.close()

# added by Daniel La 08/02/12
# method to get database size and populate custom attribute db_size on CIT DB2
def getDBSize(db2Client,db2OSH):
    rs = None
    try:
        rs = db2Client.executeQuery("select SUM(total_pages*page_size)/1024.0/1024 TOTAL_ALLOCATED_SPACE_IN_MB from table (snapshot_tbs_cfg('"+ db2Client.getDatabaseName() + "',-1)) TBS_SPCE")#@@CMD_PERMISION sql protocol execution
        while (rs.next()):
            db2OSH.setAttribute('db_size', rs.getFloat(1))
    finally:
        if rs != None:
            rs.close()

########################
#                      #
# MAIN ENTRY POINT     #
#                      #
########################
def DiscoveryMain(Framework):
    OSHVResult = ObjectStateHolderVector()
    protocolName = 'SQL'
    db2Client = None
    shellUtils = None # added by Daniel La

    try:
        try:
            db2Client = Framework.createClient()
            hostId = Framework.getDestinationAttribute('hostId')
            hostOSH = modeling.createOshByCmdbIdString('host', hostId)
            OSHVResult.add(hostOSH)

            db2Id = Framework.getDestinationAttribute('id')
            db2OSH = modeling.createOshByCmdbIdString('db2', db2Id)
            OSHVResult.add(db2OSH)

            # get details to setup shell connection to host - Daniel La
            protocol  = Framework.getDestinationAttribute('protocol')
            shellCredentialsId = Framework.getDestinationAttribute('shellCredentialsId')

            if (protocol == 'ssh'): # AIX box with DB2
                logger.debug('ssh available on host')
                if (shellCredentialsId == None or shellCredentialsId.strip().upper() == 'NA'):
                    logger.debug('no shellCredentialsId provided shellCredentialsId=%s' %shellCredentialsId)
                    shellUtils = None
                else:
                    try:
                        protocolProperties = Properties()
                        shellUtils = getShellUtils(Framework, protocol, shellCredentialsId, protocolProperties)
                    except:
                        logger.debugException('Failed creating %s shell client:' % protocol)
                        shellUtils = None

            discoverySuccessful = 1
            try:
                # getDBTablespace(db2Client, db2OSH, hostOSH, OSHVResult, shellUtils)
                getDBTablespace(db2Client, db2OSH, hostOSH, OSHVResult, shellUtils) # adjusted by Danile La
            except:
                discoverySuccessful = 0
                logger.debugException('')
                Framework.reportWarning("SQL: Failed to discover tablespaces")

            try:
                getDBSession(db2Client, db2OSH, OSHVResult)
            except:
                discoverySuccessful = 0
                logger.debugException('')
                Framework.reportWarning("SQL: Failed to discover sessions")

            # added by Daniel La 08/02/12
            # get database size
            try:
                getDBSize(db2Client, db2OSH)
            except:
                discoverySuccessful = 0
                logger.debugException('')
                Framework.reportWarning("SQL: Failed to discover db size")

            try:
                getDBSchemas(db2Client, db2OSH, OSHVResult)
            except JavaException, ex:
                logger.debugException()
                if not discoverySuccessful:
                    strException = str(ex.getMessage())
                    errormessages.resolveAndReport(strException, protocolName, Framework)
                else:
                    Framework.reportWarning("SQL: Failed to discover schemas")
            except:
                logger.debugException('')
                if not discoverySuccessful:
                    errorMsg = str(sys.exc_info()[1])
                    errormessages.resolveAndReport(errorMsg, protocolName, Framework)
                else:
                    Framework.reportWarning("SQL: Failed to discover schemas")

        except JavaException, ex:
            strException = ex.getMessage()
            errormessages.resolveAndReport(strException, ClientsConsts.SQL_PROTOCOL_NAME, Framework)
        except:
            strException = logger.prepareJythonStackTrace('')
            errormessages.resolveAndReport(strException, ClientsConsts.SQL_PROTOCOL_NAME, Framework)
    finally:
        if db2Client != None:
            db2Client.close()
        if shellUtils:              # added by Daniel La
            shellUtils.closeClient()

    return OSHVResult