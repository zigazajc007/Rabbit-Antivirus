#include <iostream>
#include <string.h>
#include <fstream>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>

using namespace std;

int total_word_lists = 389;

string toFiveDigits(int i){
    if(i > 9999){
        return "" + to_string(i);
    }else if(i > 999){
        return "0" + to_string(i);
    }else if(i > 99){
        return "00" + to_string(i);
    }else if(i > 9){
        return "000" + to_string(i);
    }else{
        return "0000" + to_string(i);
    }
}

string exec(const char* cmd) {
    array<char, 128> buffer;
    string result;
    shared_ptr<FILE> pipe(popen(cmd, "r"), pclose);
    if (!pipe) throw runtime_error("popen() failed!");
    while (!feof(pipe.get())) {
        if (fgets(buffer.data(), 128, pipe.get()) != nullptr)
            result += buffer.data();
    }
    return result;
}

void download(){
    for(int i = 0; i <= total_word_lists; i++){
        string num = toFiveDigits(i);
        ifstream ifile;
        ifile.open("VirusList/VirusShare_" + num + ".md5");
        if(!ifile){
            cout << "Downloading Word Lists " + num + "/00389 (" + to_string((100.0/total_word_lists)*i) + "%)" << '\r' << flush;
            system(("wget -q -P VirusList https://virusshare.com/hashfiles/VirusShare_" + num + ".md5").c_str());
        }
        ifile.close();
    }
    printf("\n\033[1;32mDownload finished!\n");
}

int scan(string file){
    ifstream ifile;
    ifile.open(file);
    if(ifile){
        int scanned = 0;
        string md5sum = exec(("md5sum " + file).c_str()).substr(0, 32);
        cout << "MD5 hash: " << md5sum << endl;
        for(int i = 0; i <= total_word_lists; i++){
            string num = toFiveDigits(i);
            ifstream wfile;
            wfile.open("VirusList/VirusShare_" + num + ".md5");
            if(wfile.is_open()){
                string md5_hash;
                while(getline(wfile, md5_hash)){
                    cout << "Scanning file... " + to_string(scanned) + "/35258368 (" + to_string((100.0/35258368)*scanned) + "%)" << '\r' << flush;
                    if(md5sum == md5_hash)return 2;
                    scanned++;
                }
                wfile.close();
            }
        }
        ifile.close();
        return 1;
    }else{
        ifile.close();
        return 0;
    }
}

int main(int argc, char *argv[]){
    cout << "\n\n\n\033[1;32m";
    cout << "██████╗  █████╗ ██████╗ ██████╗ ██╗████████╗     █████╗ ███╗   ██╗████████╗██╗██╗   ██╗██╗██████╗ ██╗   ██╗███████╗\n";
    cout << "██╔══██╗██╔══██╗██╔══██╗██╔══██╗██║╚══██╔══╝    ██╔══██╗████╗  ██║╚══██╔══╝██║██║   ██║██║██╔══██╗██║   ██║██╔════╝\n";
    cout << "██████╔╝███████║██████╔╝██████╔╝██║   ██║       ███████║██╔██╗ ██║   ██║   ██║██║   ██║██║██████╔╝██║   ██║███████╗\n";
    cout << "██╔══██╗██╔══██║██╔══██╗██╔══██╗██║   ██║       ██╔══██║██║╚██╗██║   ██║   ██║╚██╗ ██╔╝██║██╔══██╗██║   ██║╚════██║\n";
    cout << "██║  ██║██║  ██║██████╔╝██████╔╝██║   ██║       ██║  ██║██║ ╚████║   ██║   ██║ ╚████╔╝ ██║██║  ██║╚██████╔╝███████║\n";
    cout << "╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═════╝ ╚═╝   ╚═╝       ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═══╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝\n";
    cout << "\033[1;34mDetect more then 35.258.368 infected files!\033[1;32m\n";
    cout << "\n\n\n";

    if(argc != 1){
        if(!strcmp(argv[1], "download")){
            download();
        }else if(!strcmp(argv[1], "scan")){
            if(argc == 3){
                switch(scan(argv[2])){
                    case 0:
                        printf("\033[1;31mFile don't exists!");
                    break;
                    case 1:
                        printf("\033[1;31mFile is not on Virus list, but still be careful.");
                    break;
                    case 2:
                        printf("\033[1;31mFile is a virus! Please don't open it. You should delete it immediately!");
                    break;
                }
            }else{
                printf("\033[1;31mInvalid arguments! Please provide %s scan [FILE]", argv[0]);
            }
        }else if(!strcmp(argv[1], "help")){
            printf("Available arguments:\n\thelp - Show all avaliable arguments\n\tdownload - download list of infected files in md5 format\n\tscan [FILE] - Scan specific file if it is infected");
        }else{
            printf("\033[1;31mInvalid arguments!");
        }
    }else{
        printf("\033[1;31mInvalid arguments! Please execute %s help for more information.", argv[0]);
    }

    printf("\n");
    return 0;
}
