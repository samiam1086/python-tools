# python-tools

## slowspray.py

slowspray is a Python tool using Impacket to password spray a Windows Domain with a delay to evade being blocked by defenses.

## secretsdumpplus.py

secretsdumpplus is a fork of Impacket's secretsdump.py example to include multithreading and the ability to target more than one machine at a time outputting files to a default loot directory.

## netNtlm-uniq.py

netNtlm-uniq works the same as the uniq command in bash, however it is designed to be used for netNTLMv1 and v2 hashes that are salted.

## gen-userlist.py

gen-userlist is a tool that requires SecLists to be downloaded. gen-userlist will use the list of firstnames and lastnames within SecLists to create an extremely large list of potential usernames in common formats that enterprises use. This can be comnined with Kerbrute's userenum to get a list of valid usernames that can be password sprayed.

## difforsame.py

difforsame is a slightly more helpful version of the diff command.

## newline-to-space.py

newline-to-space - self expanatory.
