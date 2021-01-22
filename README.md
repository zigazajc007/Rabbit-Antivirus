# Rabbit-Antivirus

Simple Antivirus that will download md5 hashes of viruses from https://virusshare.com and then compare your files with known viruses. If hash will match Antivirus will notify you and you will be able to make an action.

## Depencencies
* wget
* md5sum

## Commands
* ./rav help - Show all avaliable arguments
* ./rav download - download list of infected files in md5 format
* ./rav check [FILE] - Scan specific file if it is infected

## Pictures
![Rabbit Antivirus](https://i.imgur.com/5vwluJk.png)
