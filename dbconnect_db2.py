#coding=utf-8
##############################################
## DB2 identification methods for DB_Connect_by_TTY/Agent
## Vinay Seshadri
## UCMDB CORD
## Jan 14, 2008
##############################################

## Jython imports
import re

## Local helper scripts on probe
import logger
import shellutils
## DB Connect helper scripts
import dbconnect_utils
import shell_interpreter

##############################################
## Globals
##############################################
SCRIPT_NAME="dbconnect_db2.py"

##############################################
## Find databases
##############################################
def findDatabases(localClient, procToPortDict, dbInstanceDict, isWindows='true', wmiRegistryClient=None):
    try:
        ## DB2 cannot be discovered through an SNMP/WMI agent
        localClientType = localClient.getClientType()
        if localClientType not in ['telnet', 'ssh', 'ntadmin']:
            logger.error('[' + SCRIPT_NAME + ':findDatabase] DB2 discovery requires SSH/Telnet/NTCMD')
            return

        ## The best approach to find DB2 instances is to make a list of
        ## locations where DB2 may be installed and search through them.
        searchLocations = []
        ## Extract information from process to port dictionary first
        ## For DB2, it is not possible to get database details from this
        ## dictionary. the best approach is to get possible install
        ## locations of DB2 and find databases later
        processProcToPortDict(localClient, isWindows, procToPortDict, searchLocations)

        ## Use the list of possible install locations to identify valid
        ## install locations
        instanceLocations = getInstancePaths(localClient, isWindows, searchLocations)

        # used for debugging purposes only - Daniel La
        for instancePath in instanceLocations:
            logger.debug('***********instance path is: ' + instancePath)

        ## Get databases using instance locations
        if instanceLocations:
            getDatabases(localClient, isWindows, instanceLocations, dbInstanceDict)
    except:
        excInfo = logger.prepareJythonStackTrace('')
        dbconnect_utils.debugPrint('[' + SCRIPT_NAME + ':findDatabases] Exception: <%s>' % excInfo)
        pass

##############################################
## Extract information from process to port dictionary
##############################################
def processProcToPortDict(localClient, isWindows, p2pDict, possibleInstallLocations):
    try:
        dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':processProcToPortDict]')
        localShellUtils = shellutils.ShellUtils(localClient)
        windowsServer = localShellUtils.isWinOs()
        ## Some locals to avoid searching the same locations more than once
        checkedPaths = []
        for pid in p2pDict.keys():
            processName = (p2pDict[pid])[dbconnect_utils.PROCESSNAME_INDEX].lower()
            listenerPort = (p2pDict[pid])[dbconnect_utils.PORT_INDEX]
            ipAddress = (p2pDict[pid])[dbconnect_utils.IP_INDEX]
            if ipAddress == dbconnect_utils.UNKNOWN:
                ipAddress = localClient.getIpAddress()
            path = (p2pDict[pid])[dbconnect_utils.PATH_INDEX]
            statusFlag = (p2pDict[pid])[dbconnect_utils.STATUS_INDEX]
            userName = (p2pDict[pid])[dbconnect_utils.USER_INDEX]
            ## **** This is a dummy filter for now and will be populated
            ## **** with more info as and when available
            if re.search('some_non_db2_process', processName):
                ## Filters: If we don't skip these, the next checks will
                ## catch them and identify incorrect instances
                dbconnect_utils.debugPrint(4, '[' + SCRIPT_NAME + ':processProcToPortDict] (1) Found process name <%s>. Ignoring...' % processName)
                continue
            ## Look for DB2 install locations using known process/service/software names
            elif re.search('db2', processName):

                ## Daniel La: This box has DB2. We will look for userName in /etc/passwd to find it's home directory. This home directory is what should
                ## be used to search for possible DB2 install paths. This information was provided by Felix Iwan from DB2 team.
                if dbconnect_utils.isValidString(userName):

                    passwdentry = None
                    grepCommand = 'grep ' + userName.strip() + ' /etc/passwd | grep -v root' # ignore root user account
                    passwdentry = localClient.executeCmd(grepCommand)
                    m = re.search('.*:.*:.*:.*:.*:(.*):.*', passwdentry)
                    if m:
                        userHomeDirectory = m.group(1)
                        # logger.debug('userHomeDirectory is: ', userHomeDirectory)
                        if userHomeDirectory.lower() not in checkedPaths:
                            dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':processProcToPortDict] (2.1) Found possible DB2 install path <%s>' % userHomeDirectory)
                            possibleInstallLocations.append(userHomeDirectory)
                            checkedPaths.append(userHomeDirectory.lower())

                        else:
                            dbconnect_utils.debugPrint(4, '[' + SCRIPT_NAME + ':processProcToPortDict] (2.1) Skipping path <%s> since it has been processed before' % userHomeDirectory)
                else:
                    dbconnect_utils.debugPrint(4, '[' + SCRIPT_NAME + ':processProcToPortDict] (2.1) Invalid username for process/service/software <%s>' % processName)
                # Daniel La - below is the original of the above.. I've commented it out as we are using the /etc/passwd file to determine paths to search
                # instead of prefixing usernames with /home/.

                ## This box has DB2. Check if a path and/or username are available to find DB2 instances
                #if dbconnect_utils.isValidString(userName):
                #    userHomeDirectory = '/home/%s' % userName.strip()
                #    if userHomeDirectory.lower() not in checkedPaths:
                #        dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':processProcToPortDict] (2.1) Found possible DB2 install path <%s>' % userHomeDirectory)
                #        possibleInstallLocations.append(userHomeDirectory)
                #        checkedPaths.append(userHomeDirectory.lower())
                #    else:
                #        dbconnect_utils.debugPrint(4, '[' + SCRIPT_NAME + ':processProcToPortDict] (2.1) Skipping path <%s> since it has been processed before' % userHomeDirectory)
                # else:
                #    dbconnect_utils.debugPrint(4, '[' + SCRIPT_NAME + ':processProcToPortDict] (2.1) Invalid username for process/service/software <%s>' % processName)

                if dbconnect_utils.isValidString(path):
                    logger.debug('path is: ', path) # added for debugging - Daniel La
                    ## Remove process name from the path
                    db2Path = path[:path.rfind(processName)-1]
                    ## For windows, the processName variable may contain service
                    ## names, so extract process names
                    if isWindows == 'true':
                        procNameMatch = re.search(r'.*[\\|/](\w+\.exe)', path)
                        if procNameMatch:
                            procName = procNameMatch.group(1).strip()
                            db2Path = path[:path.rfind(procName)-1]
                    if db2Path.lower() not in checkedPaths:
                        dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':processProcToPortDict] (2.2) Found possible DB2 install path <%s>' % db2Path)
                        possibleInstallLocations.append(db2Path)
                        checkedPaths.append(db2Path.lower())
                    else:
                        dbconnect_utils.debugPrint(4, '[' + SCRIPT_NAME + ':processProcToPortDict] (2.2) Skipping path <%s> since it has been processed before' % path)
                else:
                    dbconnect_utils.debugPrint(4, '[' + SCRIPT_NAME + ':processProcToPortDict] (2.2) Invalid path for process/service/software <%s>' % processName)
    except:
        excInfo = logger.prepareJythonStackTrace('')
        dbconnect_utils.debugPrint('[' + SCRIPT_NAME + ':processProcToPortDict] Exception: <%s>' % excInfo)
        pass


##############################################
## Get instance locations from search locations
##############################################
def getInstancePaths(localClient, isWindows, possibleInstallLocations):
    try:
        instancePaths = []
        ## Prepopulate possible install locations with some common directories
        if len(possibleInstallLocations) < 1:
            if isWindows == 'true':
                possibleInstallLocations.append('%HOMEDRIVE%\ibm')
                possibleInstallLocations.append('%SYSTEMDRIVE%\ibm')
                possibleInstallLocations.append('%PROGRAMFILES%\ibm')
                possibleInstallLocations.append('%PROGRAMFILES(x86)%\ibm')
                possibleInstallLocations.append('%HOMEDRIVE%\db2')
                possibleInstallLocations.append('%SYSTEMDRIVE%\db2')
                possibleInstallLocations.append('%PROGRAMFILES%\db2')
                possibleInstallLocations.append('%PROGRAMFILES(x86)%\db2')
                possibleInstallLocations.append('%DB2_HOME%')
                possibleInstallLocations.append('%DB2HOME%')
            else:
                possibleInstallLocations.append('/u01')
                possibleInstallLocations.append('/u02')
                possibleInstallLocations.append('/opt')
                possibleInstallLocations.append('/usr/opt')
                possibleInstallLocations.append('/usr/local')
                possibleInstallLocations.append('$DB2_HOME')
                possibleInstallLocations.append('$DB2HOME')

        for location in possibleInstallLocations:
            logger.debug('location to search is: ', location) # added for debugging - Daniel La
            ## Search for DB2 command processor executable
            db2cmdLocations = []
            ## DB2 command processor executable has a different name on Windows
            if isWindows == 'true':
                db2cmdLocations = dbconnect_utils.findFile(localClient, 'db2cmd.exe', location, isWindows)
            else:
                db2cmdLocations = dbconnect_utils.findFile(localClient, 'db2', location, isWindows)
            ## If an executable was found, check if it is indeed a DB2
            ## instance and extract the install path
            if db2cmdLocations and len(db2cmdLocations) > 0:
                logger.debug('location is ', db2cmdLocations) # added for debugging - Daniel La
                for db2cmdLocation in db2cmdLocations:
                    if not dbconnect_utils.isValidString(db2cmdLocation):
                        dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':getInstancePaths] (1) DB2 command processor executable found in an invalid location <%s>! Skipping...' % location)
                        continue
                    if db2cmdLocation.lower().find('sqllib') > 0:
                        logger.debug('we are here')
                        #instancePath = db2cmdLocation[:db2cmdLocation.lower().find('sqllib')-1] # Instance path is upto the "sqllib" string minus trailing slash
                        instancePath = ''
                        if isWindows == 'true':
                            instancePath = db2cmdLocation[:db2cmdLocation.rfind('\\')]
                        else:
                            instancePath = db2cmdLocation[:db2cmdLocation.rfind('/')]
                        if dbconnect_utils.isValidString(instancePath) and instancePath not in instancePaths:
#                            instanceName = ''
#                            if isWindows == 'true':
#                                instanceName = instancePath[instancePath.rfind('\\'):]
#                            else:
#                                instanceName = instancePath[instancePath.rfind('/'):]
#                            if dbconnect_utils.isValidString(instanceName) and not instanceName.strip().lower() == 'ibm':
##                                dbDict[instanceName] = ['db2', dbconnect_utils.UNKNOWN, instancePath, dbconnect_utils.UNKNOWN, localClient.getIpAddress()]
#                                dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':getInstancePaths] (1) Found DB2 command processor for instance <%s> at <%s>. Appending <%s> to install locations' % (instanceName, location, instancePath))
#                            else:
#                                dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':getInstancePaths] (1) Found DB2 command processor at <%s> with an invalid instance name! Skipping...' % location)
#                                continue
                            instancePaths.append(instancePath)
                        else:
                            dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':getInstancePaths] (1) Found DB2 command processor at <%s> already in install locations' % location)
                            continue
                    else:
                        dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':getInstancePaths] (1) DB2 command processor executable found in <%s> does not contain "sqllib" in its path. This is most likely not valid for DB2...skipping!' % location)
                        continue
            else:
                dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':getInstancePaths] (1) No DB2 command processor found in <%s>' % location)
                continue

#            ## Search for db2set executable
#            db2setLocations = dbconnect_utils.findFile(localClient, 'db2set', location, isWindows)
#            ## If an executable was found, check if it is indeed a DB2
#            ## instance and extract the install path
#            if db2setLocations and len(db2setLocations) > 1:
#                for db2setLocation in db2setLocations:
#                    if not dbconnect_utils.isValidString(db2setLocation):
#                        dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':getInstancePaths] (2) db2set executable found in an invalid location...skipping!' % location)
#                        continue
#                    if db2setLocation.lower().find('sqllib') > 0:
#                        instancePath = db2setLocation[:db2setLocation.lower().find('sqllib')]
#                        if dbconnect_utils.isValidString(instancePath) and instancePath not in instancePaths:
#                            instanceName = ''
#                            if isWindows == 'true':
#                                instanceName = instancePath[instancePath.rfind('\\'):]
#                            else:
#                                instanceName = instancePath[instancePath.rfind('/'):]
#                            if dbconnect_utils.isValidString(instanceName):
##                                dbDict[instanceName] = ['db2', dbconnect_utils.UNKNOWN, instancePath, dbconnect_utils.UNKNOWN, localClient.getIpAddress()]
#                                dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':getInstancePaths] (1) Found DB2 command processor for instance <%s> at <%s>. Appending <%s> to install locations' % (instanceName, location, instancePath))
#                            else:
#                                dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':getInstancePaths] (1) Found DB2 command processor at <%s> with an invalid instance name...skipping!' % location)
#                                continue
#                            instancePaths.append(instancePath)
#                        else:
#                            dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':getInstancePaths] (2) Found db2set at <%s> already in install locations' % location)
#                    else:
#                        dbconnect_utils.debugPrint(4, '[' + SCRIPT_NAME + ':getInstancePaths] (2) db2set executable found in <%s> does not contain "sqllib" in its path. This is most likely not valid for DB2...skipping!' % location)
#                        continue
#            else:
#                dbconnect_utils.debugPrint(4, '[' + SCRIPT_NAME + ':getInstancePaths] (2) No db2set executable found in <%s>' % location)
#                continue
        return instancePaths
    except:
        excInfo = logger.prepareJythonStackTrace('')
        dbconnect_utils.debugPrint('[' + SCRIPT_NAME + ':getInstancePaths] Exception: <%s>' % excInfo)
        pass


##############################################
## Get Db Directory  - Daniel La
##############################################
def getDbDirectory(localClient, listDbDirectoryCommand):
    try:
        DbDirectory = localClient.executeCmd(listDbDirectoryCommand)
        return DbDirectory
    except:
        excInfo = logger.prepareJythonStackTrace('')
        dbconnect_utils.debugPrint('[' + SCRIPT_NAME + ':getDbDirectory] Exception: <%s>' % excInfo)
        pass

##############################################
## Get database instances - Daniel La 24/11/10
##############################################
def getDatabases(localClient, isWindows, instancePaths, dbDict):
    try:
        for instancePath in instancePaths:
            if isWindows == 'true':
                listInstancesCommand = '\"' + instancePath + '\\db2envar.bat\" && ' + '\"' + instancePath + '\\db2ilist\"'
                listInstancesOutput = localClient.executeCmd(listInstancesCommand)
                listInstances = dbconnect_utils.splitCommandOutput(listInstancesOutput)

                logger.debug('length is: ', len(listInstances))

                for instance in listInstances:
                    listenerPort = getListenerPort(localClient, isWindows, instancePath, instance)

                    listDbDirectoryCommand = '(\"' + instancePath + '\\db2envar.bat\") && ' + '(set DB2INSTANCE=' + instance + ') && ' + '(\"' + instancePath + '\\db2cmd\" /c /w /i db2 list db directory)'
                    listDbDirectoryOutput = localClient.executeCmd(listDbDirectoryCommand)
                    if not listDbDirectoryOutput or not re.search('entry:', listDbDirectoryOutput):
                        dbconnect_utils.debugPrint(2, '[' + SCRIPT_NAME + ':getDatabases] Invalid output from command db2 list db directory for instance at <%s>! Skipping...' % instancePath)
                        continue
                    ## Initialize variables
                    dbNameAliasDict = {}
                    ## Need to initialize the database alias here because the sequecne has alias
                    ## followed by a name and there may be more than one of each
                    databaseAlias = None

                    ## Split the command output into individial lines
                    listDbDirectoryOutputLines= dbconnect_utils.splitCommandOutput(listDbDirectoryOutput)

                    ## Get DB details one line at a time
                    for listDbDirectoryOutputLine in listDbDirectoryOutputLines:
                        logger.debug('*** outputline is: ', listDbDirectoryOutputLine)
                        ## Database alias
                        m = re.search('Database alias\s+=\s*(\S+)', listDbDirectoryOutputLine.strip())
                        if (m):
                            databaseAlias = m.group(1)
                            dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':getDatabases] Found Database Alias: <%s>' % databaseAlias)

                        ## Database name
                        m = re.search('Database name\s+=\s*(\S+)', listDbDirectoryOutputLine.strip())
                        if (m):
                            databaseName = m.group(1)
                            dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':getDatabases] Found Database Name: <%s>' % databaseName)

                        ## Directory entry type - tells whether database is local (indirect) or remote (remote)
                        m = re.search('Directory entry type\s+=\s*Indirect', listDbDirectoryOutputLine.strip())

                        if (m):
                            logger.debug('database is local: ', databaseName)
                            if databaseName and databaseName not in dbNameAliasDict.keys():
                                if databaseAlias:
                                    dbNameAliasDict[databaseName] = databaseAlias
                                else:
                                    dbNameAliasDict[databaseName] = databaseName

#    original.. without instance name.
#                    for databaseName in dbNameAliasDict.keys():
#                        dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':getDatabases] Adding DB2 instance <%s> listening at port <%s>, on <%s>, and installed in <%s>' % (databaseName, listenerPort, localClient.getIpAddress(), instancePath))
#                        dbDict[databaseName] = ['db2', listenerPort, localClient.getIpAddress(), instancePath, dbconnect_utils.UNKNOWN, dbconnect_utils.UNKNOWN]
#                        if databaseName != dbNameAliasDict[databaseName]:
#                            dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':getDatabases] Adding DB2 instance alias <%s> listening at port <%s>, on <%s>, and installed in <%s>' % (dbNameAliasDict[databaseName], listenerPort, localClient.getIpAddress(), instancePath))
#                            dbDict[dbNameAliasDict[databaseName]] = ['db2', listenerPort, localClient.getIpAddress(), instancePath, dbconnect_utils.UNKNOWN, dbconnect_utils.UNKNOWN]

                    for databaseName in dbNameAliasDict.keys():
                        dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':getDatabases] Adding DB2 database <%s> in DB2 instance <%s>, listening at port <%s>, on <%s>, and installed in <%s>' % (databaseName, instance.upper(), listenerPort, localClient.getIpAddress(), instancePath))
                        dbDict[databaseName] = ['db2', listenerPort, localClient.getIpAddress(), instancePath, dbconnect_utils.UNKNOWN, dbconnect_utils.UNKNOWN, instance.upper()]
                        if databaseName != dbNameAliasDict[databaseName]:
                            dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':getDatabases] Adding DB2 database alias <%s> in DB2 instance <%s>, listening at port <%s>, on <%s>, and installed in <%s>' % (dbNameAliasDict[databaseName], instance.upper(), listenerPort, localClient.getIpAddress(), instancePath))
                            dbDict[dbNameAliasDict[databaseName]] = ['db2', listenerPort, localClient.getIpAddress(), instancePath, dbconnect_utils.UNKNOWN, dbconnect_utils.UNKNOWN, instance.upper()]


            else: # Unix
                ## Get instance port
                listenerPort = getListenerPort(localClient, isWindows, instancePath)
                listDbDirectoryOutput = None
                listDbDirectoryCommand = 'unset LIBPATH; cd ' + instancePath + '/../; . ./db2profile; ' + 'export DB2NODE=127.0.0.1; ' + instancePath + '/db2 list db directory; ' + instancePath + '/db2 terminate' # modified by Daniel La 22/11/10

                logger.debug('before')
                listDbDirectoryOutput = getDbDirectory(localClient, listDbDirectoryCommand)
                logger.debug('after')

                if not listDbDirectoryOutput or not re.search('entry:', listDbDirectoryOutput):
                    dbconnect_utils.debugPrint(2, '[' + SCRIPT_NAME + ':getDatabases] Invalid output from command db2 list db directory for instance at <%s>! Skipping...' % instancePath)
                    continue

                logger.debug('after after')

                instanceCommand = 'echo $DB2INSTANCE'

                instance = (localClient.executeCmd(instanceCommand)).strip().upper()

                logger.debug('instance is: ', instance)

                ## Initialize variables
                dbNameAliasDict = {}
                ## Need to initialize the database alias here because the sequecne has alias
                ## followed by a name and there may be more than one of each
                databaseAlias = None

                ## Split the command output into individial lines
                listDbDirectoryOutputLines= dbconnect_utils.splitCommandOutput(listDbDirectoryOutput)

                ## Get DB details one line at a time
                for listDbDirectoryOutputLine in listDbDirectoryOutputLines:
                    # logger.debug('*** outputline is: ', listDbDirectoryOutputLine)
                    ## Database alias
                    m = re.search('Database alias\s+=\s*(\S+)', listDbDirectoryOutputLine.strip())
                    if (m):
                        databaseAlias = m.group(1)
                        dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':getDatabases] Found Database Alias: <%s>' % databaseAlias)
                    ## Database name
                    m = re.search('Database name\s+=\s*(\S+)', listDbDirectoryOutputLine.strip())
                    if (m):
                        databaseName = m.group(1)
                        dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':getDatabases] Found Database Name: <%s>' % databaseName)

                    ## Directory entry type - tells whether database is local (indirect) or remote (remote)
                    m = re.search('Directory entry type\s+=\s*Indirect', listDbDirectoryOutputLine.strip())
                    if (m):
                        logger.debug('database is local: ', databaseName)
                        if databaseName and databaseName not in dbNameAliasDict.keys():
                            if databaseAlias:
                                dbNameAliasDict[databaseName] = databaseAlias
                            else:
                                dbNameAliasDict[databaseName] = databaseName

#                for databaseName in dbNameAliasDict.keys():
#                    dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':getDatabases] Adding DB2 instance <%s> listening at port <%s>, on <%s>, and installed in <%s>' % (databaseName, listenerPort, localClient.getIpAddress(), instancePath))
#                    dbDict[databaseName] = ['db2', listenerPort, localClient.getIpAddress(), instancePath, dbconnect_utils.UNKNOWN, dbconnect_utils.UNKNOWN]
#                    if databaseName != dbNameAliasDict[databaseName]:
#                        dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':getDatabases] Adding DB2 instance alias <%s> listening at port <%s>, on <%s>, and installed in <%s>' % (dbNameAliasDict[databaseName], listenerPort, localClient.getIpAddress(), instancePath))
#                        dbDict[dbNameAliasDict[databaseName]] = ['db2', listenerPort, localClient.getIpAddress(), instancePath, dbconnect_utils.UNKNOWN, dbconnect_utils.UNKNOWN]

                for databaseName in dbNameAliasDict.keys():
                    dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':getDatabases] Adding DB2 database <%s> in DB2 instance <%s>, listening at port <%s>, on <%s>, and installed in <%s>' % (databaseName, instance, listenerPort, localClient.getIpAddress(), instancePath))
                    dbDict[databaseName] = ['db2', listenerPort, localClient.getIpAddress(), instancePath, dbconnect_utils.UNKNOWN, dbconnect_utils.UNKNOWN, instance]
                    if databaseName != dbNameAliasDict[databaseName]:
                        dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':getDatabases] Adding DB2 database alias <%s> in DB2 instance <%s>, listening at port <%s>, on <%s>, and installed in <%s>' % (dbNameAliasDict[databaseName], instance, listenerPort, localClient.getIpAddress(), instancePath))
                        dbDict[dbNameAliasDict[databaseName]] = ['db2', listenerPort, localClient.getIpAddress(), instancePath, dbconnect_utils.UNKNOWN, dbconnect_utils.UNKNOWN, instance]

    except:
        excInfo = logger.prepareJythonStackTrace('')
        dbconnect_utils.debugPrint('[' + SCRIPT_NAME + ':getDatabaseInstances] Exception: <%s>' % excInfo)
        pass


##############################################
## Get listener port for a given database instance - Updated by Daniel La
##############################################
def getListenerPort(localClient, isWindows, instancePath, instance=None):
    try:
        returnPort = dbconnect_utils.UNKNOWN

        getDbmConfigOutput = None
#        getDbmConfigCommand = 'export DB2NODE=127.0.0.1; ' + instancePath + '/db2 get dbm config; db2 terminate'   original
#        getDbmConfigCommand = 'export DB2NODE=127.0.0.1; ' + instancePath + '/db2 get dbm config; ' + instancePath + '/db2 terminate' # modified by Daniel La
#        getDbmConfigCommand = '. ' + instancePath + '/../db2profile; ' + 'export DB2NODE=127.0.0.1; ' + instancePath + '/db2 get dbm config; ' + instancePath + '/db2 terminate' # modified by Daniel La
        getDbmConfigCommand = 'unset LIBPATH; cd ' + instancePath + '/../; . ./db2profile; ' + 'export DB2NODE=127.0.0.1; ' + instancePath + '/db2 get dbm config; ' + instancePath + '/db2 terminate' # modified by Daniel La
        if isWindows == 'true':
            getDbmConfigCommand = '(\"' + instancePath + '\\db2envar.bat\") && ' + '(set DB2INSTANCE=' + instance + ') && ' + '(\"' + instancePath + '\\db2cmd\" /c /w /i db2 get dbm config)'

        getDbmConfigOutput = localClient.executeCmd(getDbmConfigCommand)

        if not getDbmConfigOutput or not re.search('Database Manager Configuration', getDbmConfigOutput):
            dbconnect_utils.debugPrint(2, '[' + SCRIPT_NAME + ':getListenerPort] Invalid output from command db2 list db directory for instance at <%s>! Skipping...' % instancePath)
            return returnPort

        ## Split the command output into individial lines
        getDbmConfigOutputLines= dbconnect_utils.splitCommandOutput(getDbmConfigOutput)
        serviceName = None
        ## Get service name of this instance
        for getDbmConfigOutputLine in getDbmConfigOutputLines:
            ## Only one line will have the service name and
            ## nothing else is required from this command output
            if serviceName:
                continue
            ## Service name
            m = re.search('TCP/IP [Ss]ervice [Nn]ame\s+\(([^)]+)\)\s*=\s*(\S+)', getDbmConfigOutputLine)
            if (m):
                serviceName = m.group(2)
                dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':getListenerPort] (1) Found service name <%s> for instance in path <%s>' % (serviceName, instancePath))

            ## This may be in two separate lines
            parseService = 0
            if (re.search('TCP/IP [Ss]ervice', getDbmConfigOutputLine)):
                parseService = 1
                continue
            m = re.search('[Nn]ame\s+\(([^)]+)\)\s*=\s*(\S+)', getDbmConfigOutputLine)
            if parseService and m:
                parseService = 0
                serviceName = m.group(2)
                dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':getListenerPort] (2) Found service name <%s> for instance in path <%s>' % (serviceName, instancePath))

        ## Get the port number from services config file
        if serviceName:
#            getPortCommand = 'cat /etc/services | grep %s' % serviceName   # original
            getPortCommand = 'cat /etc/services | grep -w %s' % serviceName # updated to include -w option for direct word match - Daniel La 24/11/10

            getPortCommand2 = 'type %%WINDIR%%\\system32\\drivers\\etc\\services' # altered by Daniel La
            getPortCommand2 = 'echo %%WINDIR%%' # altered by Daniel La
            getPortCommandOutput2 = localClient.executeCmd(getPortCommand2)

            if isWindows == 'true':
                #getPortCommand = 'type %%WINDIR%%\\system32\\drivers\\etc\\services | find "%s"' % serviceName
                getPortCommand = 'type %%WINDIR%%\\system32\\drivers\\etc\\services | findstr /I "%s\>"' % serviceName # altered by Daniel La


            getPortCommandOutput = localClient.executeCmd(getPortCommand)

            if not getPortCommandOutput or not re.search('tcp', getPortCommandOutput):
                dbconnect_utils.debugPrint(2, '[' + SCRIPT_NAME + ':getListenerPort] Unable to get port number from services file for instance at <%s> with service name <%s>' % (instancePath, serviceName))
                return returnPort

            m = re.search('^\s*(\S+)\s+(\d+).*$', getPortCommandOutput.strip())
            if (m):
                returnPort = m.group(2)

        return returnPort
    except:
        excInfo = logger.prepareJythonStackTrace('')
        dbconnect_utils.debugPrint('[' + SCRIPT_NAME + ':getListenerPort] Exception: <%s>' % excInfo)
        pass


'''
# Below is the original code for getDatabases() and getListenerPort() - Daniel La

##############################################
## Get database instances
##############################################
def getDatabases(localClient, isWindows, instancePaths, dbDict):
    try:
        for instancePath in instancePaths:
            ## Get instance port
            listenerPort = getListenerPort(localClient, isWindows, instancePath)
            listDbDirectoryOutput = None
            shell = shellutils.ShellFactory().createShell(localClient)
            environment = shell_interpreter.Factory().create(shell).getEnvironment()
            environment.setVariable('DB2NODE', '127.0.0.1')
            listDbDirectoryCommand = instancePath + '/db2 list db directory; db2 terminate'
            if isWindows == 'true':
                listDbDirectoryCommand = instancePath + '\\db2cmd /c /w /i db2 list db directory'

            listDbDirectoryOutput = localClient.executeCmd(listDbDirectoryCommand)

            if not listDbDirectoryOutput or not re.search('entry:', listDbDirectoryOutput):
                dbconnect_utils.debugPrint(2, '[' + SCRIPT_NAME + ':getDatabases] Invalid output from command db2 list db directory for instance at <%s>! Skipping...' % instancePath)
                continue

            ## Initialize variables
            dbNameAliasDict = {}
            ## Need to initialize the database alias here because the sequecne has alias
            ## followed by a name and there may be more than one of each
            databaseAlias = None

            ## Split the command output into individial lines
            listDbDirectoryOutputLines= dbconnect_utils.splitCommandOutput(listDbDirectoryOutput)

            ## Get DB details one line at a time
            for listDbDirectoryOutputLine in listDbDirectoryOutputLines:
                ## Database alias
                m = re.search('Database alias\s+=\s*(\S+)', listDbDirectoryOutputLine.strip())
                if (m):
                    databaseAlias = m.group(1)
                    dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':getDatabases] Found Database Alias: <%s>' % databaseAlias)
                ## Database name
                m = re.search('Database name\s+=\s*(\S+)', listDbDirectoryOutputLine.strip())
                if (m):
                    databaseName = m.group(1)
                    dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':getDatabases] Found Database Name: <%s>' % databaseName)
                    if databaseName and databaseName not in dbNameAliasDict.keys():
                        if databaseAlias:
                            dbNameAliasDict[databaseName] = databaseAlias
                        else:
                            dbNameAliasDict[databaseName] = databaseName

            for databaseName in dbNameAliasDict.keys():
                dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':getDatabases] Adding DB2 instance <%s> listening at port <%s>, on <%s>, and installed in <%s>' % (databaseName, listenerPort, localClient.getIpAddress(), instancePath))
                dbDict[databaseName] = ['db2', listenerPort, localClient.getIpAddress(), instancePath, dbconnect_utils.UNKNOWN, dbconnect_utils.UNKNOWN]
                if databaseName != dbNameAliasDict[databaseName]:
                    dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':getDatabases] Adding DB2 instance alias <%s> listening at port <%s>, on <%s>, and installed in <%s>' % (dbNameAliasDict[databaseName], listenerPort, localClient.getIpAddress(), instancePath))
                    dbDict[dbNameAliasDict[databaseName]] = ['db2', listenerPort, localClient.getIpAddress(), instancePath, dbconnect_utils.UNKNOWN, dbconnect_utils.UNKNOWN]
    except:
        excInfo = logger.prepareJythonStackTrace('')
        dbconnect_utils.debugPrint('[' + SCRIPT_NAME + ':getDatabaseInstances] Exception: <%s>' % excInfo)
        pass


##############################################
## Get listener port for a given database instance
##############################################
def getListenerPort(localClient, isWindows, instancePath):
    try:
        returnPort = dbconnect_utils.UNKNOWN

        getDbmConfigOutput = None
        shell = shellutils.ShellFactory().createShell(localClient)
        environment = shell_interpreter.Factory().create(shell).getEnvironment()
        environment.setVariable('DB2NODE', '127.0.0.1')
        getDbmConfigCommand = instancePath + '/db2 get dbm config; db2 terminate'
        if isWindows == 'true':
            getDbmConfigCommand = instancePath + '\\db2cmd /c /w /i db2 get dbm config'

        getDbmConfigOutput = localClient.executeCmd(getDbmConfigCommand)

        if not getDbmConfigOutput or not re.search('Database Manager Configuration', getDbmConfigOutput):
            dbconnect_utils.debugPrint(2, '[' + SCRIPT_NAME + ':getListenerPort] Invalid output from command db2 list db directory for instance at <%s>! Skipping...' % instancePath)
            return returnPort

        ## Split the command output into individial lines
        getDbmConfigOutputLines= dbconnect_utils.splitCommandOutput(getDbmConfigOutput)
        serviceName = None
        ## Get service name of this instance
        for getDbmConfigOutputLine in getDbmConfigOutputLines:
            ## Only one line will have the service name and
            ## nothing else is required from this command output
            if serviceName:
                continue
            ## Service name
            m = re.search('TCP/IP [Ss]ervice [Nn]ame\s+\(([^)]+)\)\s*=\s*(\S+)', getDbmConfigOutputLine)
            if (m):
                serviceName = m.group(2)
                dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':getListenerPort] (1) Found service name <%s> for instance in path <%s>' % (serviceName, instancePath))

            ## This may be in two separate lines
            parseService = 0
            if (re.search('TCP/IP [Ss]ervice', getDbmConfigOutputLine)):
                parseService = 1
                continue
            m = re.search('[Nn]ame\s+\(([^)]+)\)\s*=\s*(\S+)', getDbmConfigOutputLine)
            if parseService and m:
                parseService = 0
                serviceName = m.group(2)
                dbconnect_utils.debugPrint(3, '[' + SCRIPT_NAME + ':getListenerPort] (2) Found service name <%s> for instance in path <%s>' % (serviceName, instancePath))

        ## Get the port number from services config file
        if serviceName:
            getPortCommand = 'cat /etc/services | grep %s' % serviceName
            if isWindows == 'true':
                getPortCommand = 'type %%WINDIR%%\\system32\\drivers\\etc\\services | find "%s"' % serviceName

            getPortCommandOutput = localClient.executeCmd(getPortCommand)
            if not getPortCommandOutput or not re.search('tcp', getPortCommandOutput):
                dbconnect_utils.debugPrint(2, '[' + SCRIPT_NAME + ':getListenerPort] Unable to get port number from services file for instance at <%s> with service name <%s>' % (instancePath, serviceName))
                return returnPort

            m = re.search('^\s*(\S+)\s+(\d+).*$', getPortCommandOutput.strip())
            if (m):
                returnPort = m.group(2)

        return returnPort
    except:
        excInfo = logger.prepareJythonStackTrace('')
        dbconnect_utils.debugPrint('[' + SCRIPT_NAME + ':getListenerPort] Exception: <%s>' % excInfo)
        pass

'''