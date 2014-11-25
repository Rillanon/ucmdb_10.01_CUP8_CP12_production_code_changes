#coding=utf-8
##############################################
## Oracle identification methods for DB_Connect_by_TTY/Agent
## Vinay Seshadri
## UCMDB CORD
## Oct 24, 2008
##############################################

## Jython imports
import re

## Local helper scripts on probe
import logger
import dbutils
## DB Connect helper scripts
import dbconnect_utils


##############################################
## Globals
##############################################
SCRIPT_NAME="dbconnect_oracle.py"

##############################################
## Find databases
##############################################
def findDatabases(localClient, procToPortDict, dbInstanceDict, isWindows='true', wmiRegistryClient=None):
    try:
        ## Extract information from process to port dictionary first
        processProcToPortDict(localClient, procToPortDict, dbInstanceDict)

        # Commented out below by Daniel La 06/01/11 - Been told not to detect Oracle DBs through these files. So only look
        # at services and processes to get DB instance names. Also tnsnames.ora may not necessarily be on the Oracle server. This file is used
        # on an Oracle client.

        ## Search for tnsnames.ora if we have a shell connection
#        if localClient.getClientType() != 'wmi' and localClient.getClientType() != 'snmp':
#            install_locs = parseEtcFiles(localClient, procToPortDict, dbInstanceDict, isWindows)
#            findTnsnamesOra(localClient, procToPortDict, dbInstanceDict, isWindows, install_locs)
    except:
        excInfo = logger.prepareJythonStackTrace('')
        dbconnect_utils.debugPrint('[' + SCRIPT_NAME + ':findDatabases] Exception: <%s>' % excInfo)
        pass

##############################################
## Extract information from process to port dictionary
## Updated by Daniel La: this method will only set listening port for Oracle DB's when there is only one listener listening on one port.
## For all other cases, no port is set for found Oracle DBs.
##############################################
def processProcToPortDict(localClient, p2pDict, dbDict):
    try:
        dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':processProcToPortDict]')
        tnslsnrPort = dbconnect_utils.UNKNOWN
        tnslsnrIp = dbconnect_utils.UNKNOWN
        installPath = dbconnect_utils.UNKNOWN

        # check how many TNS listener entries there are. If there are more than one,
        # then we don't set listening port information for Oracle DBs.
        # If there is only one, then we can set.
        # Daniel La
        totaltnslsnr = 0;
        for pid in p2pDict.keys():
            processName = (p2pDict[pid])[dbconnect_utils.PROCESSNAME_INDEX].lower()
            if re.search('tnslsnr', processName) or re.search('tnslistener', processName):
                logger.debug('listener pid: ', pid, ' listener procname: ', processName, ' port: ', (p2pDict[pid])[dbconnect_utils.PORT_INDEX])
                if (p2pDict[pid])[dbconnect_utils.PORT_INDEX] != 'UNKNOWN':
                    totaltnslsnr += 1
        logger.debug('total tnslsnr entries with valid listening port: ', totaltnslsnr)

        for pid in p2pDict.keys():
            processName = (p2pDict[pid])[dbconnect_utils.PROCESSNAME_INDEX].lower()
            listenerPort = (p2pDict[pid])[dbconnect_utils.PORT_INDEX]
            ipAddress = (p2pDict[pid])[dbconnect_utils.IP_INDEX]
            if ipAddress == dbconnect_utils.UNKNOWN:
                ipAddress = localClient.getIpAddress()
            path = (p2pDict[pid])[dbconnect_utils.PATH_INDEX]
            version = dbconnect_utils.UNKNOWN
            statusFlag = (p2pDict[pid])[dbconnect_utils.STATUS_INDEX]
            sidFound = ''
            ## See if a TNS listener is present
            ## If present, get the listener port and install path
            if re.search('tnslsnr', processName) or re.search('tnslistener', processName):
                tnslsnrPort = listenerPort
                tnslsnrIp = ipAddress
                binPath = path[:path.strip().lower().find('tnslsnr')]
                installPath = binPath[:len(binPath)-4]
                dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':processProcToPortDict] (1) Found TNS Listener at port <%s> from process <%s> with path <%s>' % (listenerPort, processName, path))
            ## Next, check for oracle process and service names to extract SID
            elif re.search('dbconsole', processName) or re.search('jobscheduler', processName) or re.search('oradb10g', processName) or re.search('oracleora9ias_', processName) or re.search('oracle-oracleas_', processName) or re.search('oradb11g', processName) or re.search('mtsrecovery', processName) or re.search('remexec', processName):
                dbconnect_utils.debugPrint(4, '[' + SCRIPT_NAME + ':processProcToPortDict] (2) Found process name <%s>. Ignoring...' % processName)
                ## If we don't filter these out, the next check for "oracle"
                ## will catch it and create a database with incorrect SIDs
                continue
            elif re.search('oracleservice', processName):
                sidRegexStr = re.search('oracleservice(\w+)', processName)
                if sidRegexStr:
                    sidFound = sidRegexStr.group(1).strip()
                    dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':processProcToPortDict] (3) Found Oracle instance <%s> from process name <%s> and its path is <%s>' % (sidFound, processName, path))
            # Commented out by Daniel La 11/01/11
            # Creating wrong Oracle DB CI's.
            # elif re.search('oracle', processName):
                # sidRegexStr = re.search('oracle(\w+)', processName)
                # if sidRegexStr:
                #    sidFound = sidRegexStr.group(1).strip()
                #    dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':processProcToPortDict] (4) Found Oracle instance <%s> from process name <%s> and its path is <%s>' % (sidFound, processName, path))
            elif re.search('ora_pmon', processName):
                sidRegexStr = re.search('ora_pmon_(\w+)', processName)
                if sidRegexStr:
                    sidFound = sidRegexStr.group(1).strip()
                    dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':processProcToPortDict] (5) Found Oracle instance <%s> from process name <%s> and its path is <%s>' % (sidFound, processName, path))

            if sidFound != None and sidFound != '' and len(sidFound) >0 and sidFound not in dbDict.keys():
                #dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':processProcToPortDict] Adding Oracle instance <%s> listening at port <%s>, on <%s>, and installed in <%s>' % (sidFound, tnslsnrPort, ipAddress, installPath))
                #dbDict[sidFound] = ['oracle', tnslsnrPort, tnslsnrIp, installPath, version, statusFlag]
                if totaltnslsnr > 1:
                    dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':processProcToPortDict] Adding Oracle instance <%s> listening at port UNKNOWN, on <%s>, and installed in UNKNOWN' % (sidFound, ipAddress))
                    dbDict[sidFound] = ['oracle', dbconnect_utils.UNKNOWN, ipAddress, dbconnect_utils.UNKNOWN, version, statusFlag]
                else:
                    dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':processProcToPortDict] Adding Oracle instance <%s> listening at port <%s>, on <%s>, and installed in <%s>' % (sidFound, tnslsnrPort, ipAddress, installPath))
                    dbDict[sidFound] = ['oracle', tnslsnrPort, tnslsnrIp, installPath, version, statusFlag]


        ## Set path and port to latest available info from TNS process if unknown
        for sid in dbDict.keys():
            ## Set port to latest TNS listener port if unknown
            # if (dbDict[sid])[dbconnect_utils.PORT_INDEX] == dbconnect_utils.UNKNOWN:
            if (dbDict[sid])[dbconnect_utils.PORT_INDEX] == dbconnect_utils.UNKNOWN and totaltnslsnr == 1:
                (dbDict[sid])[dbconnect_utils.PORT_INDEX] = tnslsnrPort # not sure why this line is commented out - Daniel La
                (dbDict[sid])[dbconnect_utils.IP_INDEX] = tnslsnrIp
            ## Set path to latest available path from tns listener process if unknown
            # if (dbDict[sid])[dbconnect_utils.PATH_INDEX] == dbconnect_utils.UNKNOWN:
            if (dbDict[sid])[dbconnect_utils.PATH_INDEX] == dbconnect_utils.UNKNOWN and totaltnslsnr == 1:
                (dbDict[sid])[dbconnect_utils.PATH_INDEX] = installPath
    except:
        excInfo = logger.prepareJythonStackTrace('')
        dbconnect_utils.debugPrint('[' + SCRIPT_NAME + ':processProcToPortDict] Exception: <%s>' % excInfo)
        pass


##############################################
## Parse oratab and oraInst.loc files in /etc
##############################################
def parseEtcFiles(localClient, p2pDict, dbDict, isWindows):
    try:
        pathsFound = []
        ## Windows doesn't have /etc/oratab or /etc/oraInst.loc
        if isWindows == 'true':
            return
        else:
            ## Process oratab if found
            oratabLocation = dbconnect_utils.findFile(localClient, 'oratab', '/etc/', isWindows)

            if oratabLocation == None:
                dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':parseEtcFiles] oratab not found in /etc/')
            else:
                oratabContent = dbconnect_utils.getFileContent(localClient, oratabLocation[0], isWindows)
                if oratabContent:
                    oratabLines = dbconnect_utils.splitCommandOutput(oratabContent)
                    if oratabLines and len(oratabLines) > 0:
                        for oratabLine in oratabLines:
                            ## Ignore comment line or lines with nothing
                            if len(oratabLine.strip()) < 1 or  oratabLine.strip()[0] == '#':
                                continue
                            dbconnect_utils.debugPrint(4, '[' + SCRIPT_NAME + ':parseEtcFiles] [1] Processing oratab line <%s>' % oratabLine)
                            oratabLineSplit = oratabLine.strip().split(':')
                            ## Ignore lines if the format is not sid:path:startup
                            if len(oratabLineSplit) < 3:
                                dbconnect_utils.debugPrint(4, '[' + SCRIPT_NAME + ':parseEtcFiles] [1] Ignoring oratab line <%s>' % oratabLine)
                                continue
                            ## We should have an instance and its path
                            sidFound = oratabLineSplit[0].strip().lower()
                            pathFound = oratabLineSplit[1].strip().lower()
                            ipAddress = localClient.getIpAddress()
                            ## If the SID is "*", ignore it and use the path
                            if sidFound == "*":
                                dbconnect_utils.debugPrint(4, '[' + SCRIPT_NAME + ':parseEtcFiles] [1] Ignoring oracle SID <%s>' % sidFound)
                                if pathFound not in pathsFound:
                                    dbconnect_utils.debugPrint(4, '[' + SCRIPT_NAME + ':parseEtcFiles] [1] Adding path <%s> to return array' % pathFound)
                                    pathsFound.append(pathFound)
                                else:
                                    dbconnect_utils.debugPrint(4, '[' + SCRIPT_NAME + ':parseEtcFiles] [1] Found known path <%s>' % pathFound)
                                continue
                            ## If this SID already exists in the dbDict, overwrite the install path
                            ## associated with it. If not, add and entry and path
                            if sidFound in dbDict.keys():
                                (dbDict[sidFound])[dbconnect_utils.PATH_INDEX] = pathFound
                                dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':parseEtcFiiles] [1] Found known Oracle instance <%s> with path <%s> on <%s>' % (sidFound, pathFound, ipAddress))
                            else:
                                dbDict[sidFound] = ['oracle', dbconnect_utils.UNKNOWN, ipAddress, pathFound, dbconnect_utils.UNKNOWN, dbconnect_utils.UNKNOWN]
                                dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':parseEtcFiles] [1] Added Oracle instance <%s> with path <%s> on <%s>' % (sidFound, pathFound, ipAddress))
                    else:
                        dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':parseEtcFiles] [1] Invalid entries /etc/oratab: <%s>!' % oratabContent)
                else:
                    dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':parseEtcFiles] [1] Empty or invalid /etc/oratab!')

            ## Process oraInst.loc if found
            oraInstLocation = dbconnect_utils.findFile(localClient, 'oraInst.loc', '/etc/', isWindows)
            if oraInstLocation == None:
                 dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':parseEtcFiles] oraInst.loc not found in /etc/')
            else:
                oraInstContent = dbconnect_utils.getFileContent(localClient, oraInstLocation[0], isWindows)
                if oraInstContent:
                    oraInstLines = dbconnect_utils.splitCommandOutput(oraInstContent)
                    if oraInstLines and len(oraInstLines) > 0:
                        for oraInstLine in oraInstLines:
                            ## Ignore comment line or lines with nothing
                            if len(oraInstLine.strip()) < 1 or  oraInstLine.strip()[0] == '#':
                                continue
                            dbconnect_utils.debugPrint(4, '[' + SCRIPT_NAME + ':parseEtcFiles] [2] Processing oraInst line <%s>' % oraInstLine)
                            oraInstLineSplit = oraInstLine.strip().split('=')
                            ## Ignore lines if the format is not inventory_loc=<path>
                            if len(oraInstLineSplit) < 2 or oraInstLineSplit[0].strip() != 'inventory_loc':
                                dbconnect_utils.debugPrint(4, '[' + SCRIPT_NAME + ':parseEtcFiles] [2] Ignoring oraInst line <%s>' % oraInstLine)
                                continue
                            ## We should have an install path
                            pathFound = oraInstLineSplit[1].strip().lower()
                            dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':parseEtcFiles] [2] Found oracle installation path <%s>' % pathFound)
                            if pathFound not in pathsFound:
                                dbconnect_utils.debugPrint(4, '[' + SCRIPT_NAME + ':parseEtcFiles] [2] Adding path <%s> to return array' % pathFound)
                                pathsFound.append(pathFound)
                            else:
                                dbconnect_utils.debugPrint(4, '[' + SCRIPT_NAME + ':parseEtcFiles] [2] Found known path <%s>' % pathFound)
                    else:
                        dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':parseEtcFiles] [2] Invalid entries /etc/oraInst.loc: <%s>' % oraInstContent)
                else:
                    dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':parseEtcFiles] [2] Empty or invalid /etc/oraInst.loc!')
        return pathsFound
    except:
        excInfo = logger.prepareJythonStackTrace('')
        dbconnect_utils.debugPrint('[' + SCRIPT_NAME + ':parseEtcFiles] Exception: <%s>' % excInfo)
        pass


##############################################
## Find tnsnames.ora
## * First, try locations in the database dictionary
## * Second, try locations of known process/service/software names in p2p
##     dictionary
## * Then, try known/standard locations such as /u01 or c:\oracle
## * If we haven't found a tnsnames.ora so far, attempt a limited
##    file system scan
##############################################
def findTnsnamesOra(localClient, p2pDict, dbDict, isWindows, installLocs):
    try:
        ## Locals
        searchLocations = []

        # Try locations in the database dictionary
        if len(dbDict) > 0:
            logger.debug('dbDict locations')
            for sid in dbDict.keys():
                if (dbDict[sid])[dbconnect_utils.PATH_INDEX] != dbconnect_utils.UNKNOWN:
                    path = (dbDict[sid])[dbconnect_utils.PATH_INDEX].lower()
                    if path in searchLocations:
                        dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':findTnsnamesOra] [1] <%s> already in search locations' % path)
                        continue
                    elif path.find('\\') > 0 or path.find('/') >= 0:
                        dbconnect_utils.debugPrint(2, '[' + SCRIPT_NAME + ':findTnsnamesOra] [1] Adding <%s> to search locations' % path)
                        searchLocations.append(path)
                    else:
                        dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':findTnsnamesOra] [1] <%s> is not a valid path' % path)
                        continue

        # Try locations in the p2p dictionary
        if len(p2pDict) > 0:
            logger.debug('p2pDict locations')
            for pid in p2pDict.keys():
                processName = (p2pDict[pid])[dbconnect_utils.PROCESSNAME_INDEX].lower()
                path = (p2pDict[pid])[dbconnect_utils.PATH_INDEX].lower()
                if re.search('tns', processName) or re.search('dbconsole', processName) or re.search('jobscheduler', processName) or re.search('oradb', processName) or re.search('oracle', processName) or re.search('ora_', processName):
                    ## Remove /bin/tnslsnr from TNS process path
                    if re.search('/bin/tnslsnr', path):
                        path = path[:path.find('/bin/tnslsnr')]
                    if path in searchLocations:
                        dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':findTnsnamesOra] [2] <%s> already in search locations' % path)
                        continue
                    elif path.find('\\') > 0 or path.find('/') >= 0:
                        dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':findTnsnamesOra] [2] Adding <%s> to search locations' % path)
                        searchLocations.append(path)
                    else:
                        dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':findTnsnamesOra] [2] <%s> is not a valid path' % path)
                        continue

        # If we have no search locations so far, try some known/standard ones
        if 1: #len(searchLocations) < 1:
            if isWindows == 'true':
                logger.debug('additional locations')
                searchLocations.append('%HOMEDRIVE%\oracle')
                searchLocations.append('%SYSTEMDRIVE%\oracle')
                searchLocations.append('%PROGRAMFILES%\oracle')
                searchLocations.append('%PROGRAMFILES(x86)%\oracle')
                searchLocations.append('%ORA_HOME%')
                searchLocations.append('%ORACLE_HOME%')
                #searchLocations.append('%ORACLE_HOME%\\network\\admin')
            else:
                searchLocations.append('/u01')
                searchLocations.append('/u02')
                searchLocations.append('/opt')
                searchLocations.append('/usr/local')
                searchLocations.append('$ORACLE_HOME')
                #searchLocations.append('$ORACLE_HOME/network/admin')
                searchLocations.append('$ORA_HOME')
                searchLocations.append('$ORACLE_BASE')

        # Add oracle paths found from other sources
        if installLocs and len(installLocs) > 0:
            logger.debug('other locations')
            for installLoc in installLocs:
                if installLoc and len(installLoc) > 0:
                    dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':findTnsnamesOra] [3] Adding <%s> to search locations' % installLoc)
                    searchLocations.append(installLoc)

        logger.debug('list of locations...')
        for location in searchLocations:
            logger.debug('*** location: ', location)

        # Search filesystem and parse tnsnames.ora entries
        for location in searchLocations:
            tnsnamesLocations = dbconnect_utils.findFile(localClient, 'tnsnames.ora', location, isWindows)
            if tnsnamesLocations == None:
                dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':findTnsnamesOra] No tnsnames.ora found in <%s>' % location)
                continue
            for tnsnamesLocation in tnsnamesLocations:
                # We don't want the sample TNSNAMES.ORA which is
                # installed by default
                if re.search('sample', tnsnamesLocation.lower()):
                    dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':findTnsnamesOra] Skipping sample tnsnames.ora in <%s>' % tnsnamesLocation)
                    continue
                tnsnamesContent = dbconnect_utils.getFileContent(localClient, tnsnamesLocation, isWindows)
                dbconnect_utils.debugPrint(4, '[' + SCRIPT_NAME + ':findTnsnamesOra] Got content of <%s>: <%s>' % (tnsnamesLocation, tnsnamesContent))
                if tnsnamesContent != None or tnsnamesContent != '' or len(tnsnamesContent) <1:
                    tnsEntries = dbutils.parseTNSNames(tnsnamesContent, '')
                    for tnsEntry in tnsEntries:
                        sidFound = tnsEntry[3].strip().lower()
                        ## Truncate domain name if this is fully qualified SID
                        if sidFound.find('.') > 0:
                            shortSID = sidFound[:sidFound.find('.')]
                            dbconnect_utils.debugPrint(4, '[' + SCRIPT_NAME + ':findTnsnamesOra] Stripping domain from SID <%s> to <%s>' % (sidFound, shortSID))
                            sidFound = shortSID
                        tnslsnrPort = tnsEntry[2].strip().lower()
                        ipAddress = dbconnect_utils.fixIP(tnsEntry[5].strip().lower(), localClient.getIpAddress())
                        if ipAddress == dbconnect_utils.UNKNOWN:
                            dbconnect_utils.debugPrint('[' + SCRIPT_NAME + ':findTnsnamesOra] Skipping instance <%s> listening at port <%s> because it\'s IP address is not valid' % (sidFound, tnslsnrPort))
                            continue
                        if sidFound in dbDict.keys():
                            installPath = (dbDict[sidFound])[dbconnect_utils.PATH_INDEX]
                            version = (dbDict[sidFound])[dbconnect_utils.VERSION_INDEX]
                            statusFlag = (dbDict[sidFound])[dbconnect_utils.STATUS_INDEX]
                            # If port and IP are already populated, don't overwrite them
                            # because this information from active processes (above) is
                            # guaranteed to be correct and tnsnames.ora may not be up-to-date
                            ## Vinay 01/04/2010 - Commenting out conditional update below
                            ## because the port and IP for an Oracle instance is not on the Oracle
                            ## process but on the TNS listener process which may be listening for
                            ## multiple instances on different ports. This makes associating an
                            ## Oracle instance to its corresponding port impossible.
                            ## So any ports found in TNSnames.ora will be used to overwrite
                            ## previously found ports
#                            if (dbDict[sidFound])[dbconnect_utils.PORT_INDEX] != dbconnect_utils.UNKNOWN:
#                                tnslsnrPort = (dbDict[sidFound])[dbconnect_utils.PORT_INDEX]
#                            if (dbDict[sidFound])[dbconnect_utils.IP_INDEX] != dbconnect_utils.UNKNOWN:
#                                ipAddress = (dbDict[sidFound])[dbconnect_utils.IP_INDEX]
                            dbDict[sidFound] = ['oracle', tnslsnrPort, ipAddress, installPath, version, statusFlag]
                            dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':findTnsnamesOra] Found known Oracle instance <%s> listening at port <%s> on <%s>' % (sidFound, tnslsnrPort, ipAddress))
                        # Don't want to add non running databases - Daniel La
                        # else:
                        #    dbDict[sidFound] = ['oracle', tnslsnrPort, ipAddress, dbconnect_utils.UNKNOWN, dbconnect_utils.UNKNOWN, dbconnect_utils.UNKNOWN]
                        #    dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':findTnsnamesOra] Added Oracle instance <%s> listening at port <%s> on <%s>' % (sidFound, tnslsnrPort, ipAddress))
                else:
                    logger.debug('[' + SCRIPT_NAME + ':findTnsnamesOra] Invalid TNSNAMES.ORA at <%s>: <%s>' % (tnsnamesLocation, tnsnamesContent))
    except:
        excInfo = logger.prepareJythonStackTrace('')
        dbconnect_utils.debugPrint('[' + SCRIPT_NAME + ':findTnsnamesOra] Exception: <%s>' % excInfo)
        pass
