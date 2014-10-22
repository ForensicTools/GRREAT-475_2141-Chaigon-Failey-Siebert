#!/usr/bin/env python
# Copyright 2011 Google Inc. All Rights Reserved.
"""In this file we define constants that can be used by client and server."""



# Special folders we want to report back for each user. The format here is:
# registry key, folder name (relative to ProfileImagePath), protobuf name.
profile_folders = [("AppData", "Application Data", "app_data"),
                   ("Cache",
                    "AppData\\Local\\Microsoft\\Windows\\"
                    "Temporary Internet Files",
                    "cache"),
                   ("Cookies", "Cookies", "cookies"),
                   ("Desktop", "Desktop", "desktop"),
                   ("Favorites", "Favorites", "favorites"),
                   ("History",
                    "AppData\\Local\\Microsoft\\Windows\\History",
                    "history"),
                   ("Local AppData", "AppData\\Roaming", "local_app_data"),
                   ("Local Settings", "Local Settings", "local_settings"),
                   ("My Music", "Music", "my_music"),
                   ("My Pictures", "Pictures", "my_pictures"),
                   ("My Video", "Videos", "my_video"),
                   ("NetHood", "NetHood", "net_hood"),
                   ("Personal", "Documents", "personal"),
                   ("PrintHood", "PrintHood", "print_hood"),
                   ("Programs",
                    "AppData\\Roaming\\Microsoft\\Windows\\"
                    "Start Menu\\Programs",
                    "programs"),
                   ("Recent", "Recent", "recent"),
                   ("SendTo", "SendTo", "send_to"),
                   ("Start Menu",
                    "AppData\\Roaming\\Microsoft\\Windows\\Start Menu",
                    "start_menu"),
                   ("Startup",
                    "AppData\\Roaming\\Microsoft\\Windows\\"
                    "Start Menu\\Programs\\Startup",
                    "startup"),
                   ("Templates", "Templates", "templates")]


MAJOR_VERSION_WINDOWS_VISTA = 6
