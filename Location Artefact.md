# Location Artefact



### Registry

#### NTUSER.dat

Location: `C:\Users\NTUSER.dat`

##### Open/Save MRU

*track files that have been opened or saved within a Windows shell dialog box.*

- XP: Software\MLicrosoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU
- WIN7/8/10: Software\MLicrosoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePIDMRU



##### UserAssist

*GUI-based programs launched from the desktop are tracked in the launcher on a Windows System.*

- Software\Microsoft\Windows\Currentversion\Explorer\UserAssist\\{GUID}\Count



##### Last-Visited MRU

*Tracks the application executables used to open files in OpenSaveMRU and the last file path used.*

- XP: Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU
- WIN7/8/10: Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU



##### XP Search - ACMRU

*The search assistant will remember a user’s search terms for filenames, computers,or words that are inside a file.*

- XP: Software\Microsoft\Search Assistant\ACMru\####



##### Search – WordWheelQuery

*Keywords searched for from the START menu bar on a Windows 7 machine.*

- Win7/8/10: Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery



##### Recent Files

*track the last files and folders opened and is used to populate data in “Recent” menus of the Start menu.*

- Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs



##### Shell Bags

*Which folders were accessed on the local machine, the network, and/or removable devices. Evidence of previously existing folders after deletion/overwrite.*

- Software\Microsoft\Windows\Shell\BagMRU
- Software\Microsoft\Windows\Shell\Bags



##### Office Recent Files

*MS Office programs will track their own Recent Files list to make it easier for users to remember the last file they were editing.*

- Software\Microsoft\Office\VERSION\Word\FileMRU
    - 14.0 = Office 2010
    - 12.0 = Office 2007
    - 11.0 = Office 2003
    - 10.0 = Office XP
- Software\Microsoft\O¯ce\VERSION\UserMRU\LiveID_####\FileMRU
    - 15.0 = Office 365



##### Run

*Contains the locations of the programs that are set to autostart once this specific user logs into the machine.*

- Software\Microsoft\Windows\CurrentVersion\Run



##### USB

*Find User that used the Unique USB Device.*

- Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2



#### Usrclass.dat

##### Shell Bags

*Which folders were accessed on the local machine, the network, and/or removable devices. Evidence of previously existing folders after deletion/overwrite.*

- Local Settings\Software\Microsoft\Windows\Shell\Bags
- Local Settings\Software\Microsoft\Windows\Shell\BagMRU



#### SYSTEM

##### BAM/DAM

*Windows Background Activity Moderator (BAM). Provides full path of the executable file that was run on the system and last execution date/time*

* SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}
* SYSTEM\CurrentControlSet\Services\dam\UserSettings\{SID}



##### Shimcache

*Any executable run on the Windows system could be found in this key.*

* XP: CurrentControlSet\Control\SessionManager\AppCompatibility
* Win7/8/10: CurrentControlSet\Control\Session Manager\AppCompatCache



##### TimeZone

*Identifies the current system time zone.*

* CurrentControlSet\Control\TimeZoneInformation



##### USB Identification

*Track USB devices plugged into a machine.*

* CurrentControlSet\Enum\USBSTOR
* CurrentControlSet\Enum\USB



##### Drive Letter and Volume Name
*Discover the last drive letter of the USB Device when it was plugged into the machine.*

- XP: CurrentControlSet\Enum\USBSTOR
- MountedDevices



#### SOFTWARE

##### System Resource Usage Monitor (SRUM)
*Records 30 to 60 days of historical system performance .Applications run, user account responsible for each, and application and bytes sent/received per application per hour.* 

- Microsoft\WindowsNT\CurrentVersion\SRUM\Extensions {d10ca2fe-6fcf-4f6d-848e-b2e99266fa89}
- C:\Windows\System32\SRU\



##### Network History

*Identify networks that the computer has been connected to.*

- Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged
- Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed
- Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache



##### Volume Serial Number

*Discover the Volume Serial Number of the Filesystem Partition on the USB.*

- Microsoft\WindowsNT\CurrentVersion\ENDMgmt



##### Unistall program

*path to the uninstaller of a installed program*

- \Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall



#### SAM

##### Last Login

*Lists the local accounts of the system and their equivalent security identifiers.*

- Domains\Account\Users



##### Last Password Change

*Lists the last time the password of a specific local user has been changed.*

- SAM\Domains\Account\Users



### In PC

#### User

##### Windows 10 Timeline

*Win10 records recently used applications and files in a “timeline”*

- %USERPROFILE%\AppData\Local\ConnectedDevices Platform\<random-name-folder>\ActivitiesCache.db



##### Jump Lists

*The Windows 7 task bar (Jump List) is engineered to allow users to “jump” or access items they have frequently or recently used quickly and easily.*

- C:\%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations



##### Email Attachements

*Outlook*

- XP: %USERPROFILE%\Local Settings\ApplicationData\Microsoft\Outlook
- Win7/8/10: %USERPROFILE%\AppData\Local\Microsoft\Outlook



##### Browser Downloads

*Firefox and IE has a built-in download manager application which keeps a history of every file downloaded by the user.*

- Firefox
    - XP: %USERPROFILE%\Application Data\Mozilla\ Firefox\Profiles\<random text>.default\downloads.sqlite
    - Win7/8/10: %USERPROFILE%\AppData\Roaming\Mozilla\ Firefox\Profiles\<random text>.default\downloads.sqlite
- Internet Explorer
    - IE8-9: %USERPROFILE%\AppData\Roaming\Microsoft\Windows\ IEDownloadHistory\
    - IE10-11: %USERPROFILE%\AppData\Local\Microsoft\Windows\WebCache\ WebCacheV*.dat



##### Browser Search Terms / Histroy

*Records websites visited by date and time. This will also include the website history of search terms in search engines.*

- Internet Explorer
    - IE6-7: %USERPROFILE%\Local Settings\History\History.IE5
    - IE8-9: %USERPROFILE%\AppData\Local\Microsoft\Windows\History\History.IE5
    - IE10-11: %USERPROFILE%\AppData\Local\Microsoft\Windows\WebCache\WebCacheV*.dat
- Firefox
    - XP: %USERPROFILE%\Application Data\Mozilla\Firefox\Profiles\\"randomtext".default\places.sqlite
    - Win7/8/10: %USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\"randomtext".default\places.sqlite
- Chrome
    - XP: %USERPROFILE%\Local Settings\Application Data\Google\Chrome\User Data\Default\History
    - Win7/8/10: %USERPROFILE%\AppData\Local\Google\Chrome\User Data\Default\History



##### Cookies

*give insight into what websites have been visited and what activities may have taken place there.*

- Internet Explorer
    - IE6-8: %USERPROFILE%\AppData\Roaming\Microsoft\Windows\Cookies
    - IE10: %USERPROFILE%\AppData\Roaming\Microsoft\Windows\Cookies
    - IE11: %USERPROFILE%\AppData\Local\Microsoft\Windows\INetCookies
- Firefox
    - XP: %USERPROFILE%\Application Data\Mozilla\Firefox\Profiles\<random text>.default\cookies.sqlite
    - Win7/8/10: %USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<randomtext>.default\cookies.sqlite
- Chrome
    - XP: %USERPROFILE%\Local Settings\ApplicationData\Google\Chrome\User Data\Default\Local Storage
    - Win7/8/10: %USERPROFILE%\AppData\Local\Google\Chrome\User Data\Default\Local Storage



##### Flash & Super Cookies

*many sites have begun using LSOs for their tracking mechanisms because they rarely get cleared like traditional cookies.*

- Win7/8/10: %USERPROFILE%\AppData\Roaming\Macromedia\FlashPlayer\#SharedObjects\\"randomprofileid"



##### Cache

*where web page components can be stored locally to speed up subsequent visits*

- Internet Explorer
    -  IE8-9-10: %USERPROFILE%\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5
    - IE11: %USERPROFILE%\AppData\Local\Microsoft\Windows\INetCache\IE
    - Edge: %USERPROFILE%\AppData\Local\Packages\microsoft.microsoftedge_<APPID>\AC\MicrosoftEdge\Cache
- Firefox
    - XP: %USERPROFILE%\Local Settings\ApplicationData\Mozilla\Firefox\Profiles\<randomtext>.default\Cache
    - Win7/8/10: %USERPROFILE%\AppData\Local\Mozilla\Firefox\Profiles\<randomtext>.default\Cache
- Chrome
- XP: %USERPROFILE%\Local Settings\Application Data\Google\Chrome\User Data\Default\Cache - data_# and f_######
- Win7/8/10: %USERPROFILE%\AppData\Local\Google\Chrome\User Data\Default\Cache\ - data_# and f_######



##### Session Restore

*Automatic Crash Recovery features built into the browser.*

- Internet Explorer
    - Win7/8/10: %USERPROFILE%/AppData/Local/Microsoft/Internet Explorer/Recovery
- Firefox
    - Win7/8/10: %USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\"randomtext".default\sessionstore.js
- Chrome
    - Win7/8/10: %USERPROFILE%\AppData\Local\Google\Chrome\User Data\Default\



##### Thumbcache

*Thumbnails of pictures, office documents, and folders exist in a database called the thumbcache.*

- %USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer



##### Shortcut (LNK) Files

*Shortcut files automatically created by Windows.*

- XP: %USERPROFILE%\Recent
- Win7/8/10:
    - %USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent
    - %USERPROFILE%\AppData\Roaming\Microsoft\Office\Recent



##### Startup Folder

*Installed Program display in the start menu*

- ProgramData\Microsoft\Windows\Start Menu\Programs
- C:\Users\\"User"\AppData\Roaming\Microsoft\Windows\Start Menu\Programs



##### Icon Packages

*path to file who contains icons of searches of the user, file in BMP format*

- C:\Users\\"users"\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\LocalState\AppIconCache\100



#### Windows

##### Amcache.hve

*ProgramDataUpdater (a task associated with the Application Experience Service) uses the registry file Amcache.hve to store data during process creation*

- %SYSTEM ROOT%\AppCompat\Programs\Amcache.hve



##### Prefetch

*Increases performance of a system by pre-loading code pages of commonly used applications. Utilized to know an application was executed on a system.*

- %SYSTEM ROOT%\Prefetch



##### RDP Usage

*Track Remote Desktop Protocol logons to target machines.*

- %SYSTEM ROOT%\System32\winevt\logs\Security.evtx



##### Authentication Events

*Authentication mechanisms*

- %SYSTEM ROOT%\System32\winevt\logs\Security.evtx



##### USB First/Last Times

*Determine temporal usage of specific USB devices connected to a Windows Machine.*

- XP: %SYSTEM ROOT%\setupapi.log
- Win7/8/10: %SYSTEM ROOT%\inf\setupapi.dev.log



##### PnP Events

*When a Plug and Play driver install is attempted, the service will log an ID 20001 event and provide a Status within the event.*

- %system root%\System32\winevt\logs\System.evtx



#### Recycle bin

*Deleted program first go to recycle bin.*

##### XP

- C:\RECYCLER” 2000/NT/XP/2003

##### Win7/8/10

- C:\\$Recycle.bin



























