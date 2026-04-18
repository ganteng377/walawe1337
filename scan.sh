#!/bin/bash

echo -e "\e[33m=====================================================================================================\e[0m"
echo -e "\e[33m=\e[0m                                     \e[32mTools Priv8 Atengg377\e[0m"
echo -e "\e[33m=\e[0m=====================================================================================================\e[0m"
echo -e "\e[33m=\e[0m Requirement Intsall : httpx ( go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest )  \e[33m=\e[0m"
echo -e "\e[33m=\e[0m Ubah variable yang ada di script sesuai keinginan (\e[31mhttpx404\e[0m) original (\e[31mhttpx\e[0m)                     \e[33m=\e[0m"
echo -e "\e[33m=\e[0m                                      \e[32mcreated by Hengker Ganteng377 \e[0m"
echo -e "\e[33m=\e[0m=====================================================================================================\e[0m"

# Periksa jumlah argumen
if [ $# -ne 1 ]; then
    echo -e "\e[31mUsage: $0 <file_txt>\e[0m"
    exit 1
fi

file_txt="$1"

for choice in {1..18}; do
    clear
    echo -e "\e[33m=====================================================================================================\e[0m"
    echo -e "\e[33m=\e[0m                                     \e[32mTools Priv8 Atengg377\e[0m"
    echo -e "\e[33m=\e[0m=====================================================================================================\e[0m"
    echo -e "\e[32mMenu:\e[0m"
    echo -e "1. \e[33mignition\e[0m"
    echo -e "2. \e[33m.env\e[0m"
    echo -e "3. \e[33m.git\e[0m"
    echo -e "4. \e[33mphpmyadmin\e[0m"
    echo -e "5. \e[33mjfu\e[0m"
    echo -e "6. \e[33mlogout bug\e[0m"
    echo -e "7. \e[33msftp 1\e[0m"
    echo -e "8. \e[33msftp 2\e[0m"
    echo -e "9. \e[33msftp 3\e[0m"
    echo -e "10. \e[33melementor change pass\e[0m"
    echo -e "11. \e[33mjenkins\e[0m"
    echo -e "12. \e[33mEval Stdin\e[0m"
    echo -e "13. \e[33mmasterstudy wp\e[0m"
    echo -e "14. \e[33mphpinfo 1\e[0m"
    echo -e "15. \e[33mphpinfo 2\e[0m"
    echo -e "16. \e[33mphpinfo 3\e[0m"
    echo -e "17. \e[33mjquery file upload\e[0m"
    echo -e "18. \e[33mWP Fastest Cache 1.2.2 Unauthenticated SQL Injection\e[0m"
    echo -e "12. \e[33mLiveware\e[0m"
    echo -e "0. \e[31mKeluar\e[0m"

    case $choice in
        1)
            echo -e "\e[31mSi Anjing memilih Pilihan pertama\e[0m"
            dir_cari="/_ignition/execute-solution"
            respon="405"
            ms="Supported methods: POST"
            output_file="$1.laravelignition.txt"
            ;;
        2)
            echo -e "\e[31mSi Anjing memilih Pilihan kedua\e[0m"
            dir_cari="/.env"
            respon="200"
            ms="DB_DATABASE="
            output_file="$1.env.txt"
            ;;
        3)
            echo -e "\e[31mSi Anjing memilih Pilihan Ketiga\e[0m"
            dir_cari="/.git/config"
            respon="200"
            ms="repositoryformatversion"
            output_file="$1.git.txt"
            ;;
        4)
            echo -e "\e[31mSi Anjing memilih Pilihan Keempat\e[0m"
            dir_cari="/phpmyadmin"
            respon="200"
            ms="phpMyAdmin"
            output_file="$1.phpmyadmin.txt"
            ;;
        5)
            echo -e "\e[31mSi Anjing memilih Pilihan Kelima\e[0m"
            dir_cari="/upload_temp/server/php/"
            respon="200"
            ms="files"
            output_file="$1.phppgadmin.txt"
            ;;
        6)
            echo -e "\e[31mSi Anjing memilih Pilihan Keenam\e[0m"
            dir_cari="/logout"
            respon="405"
            ms="Whoops"
            output_file="$1.logout.txt"
            ;;
        7)
            echo -e "\e[31mSi Anjing memilih Pilihan Ketujuh\e[0m"
            dir_cari="/.vscode/sftp.json"
            respon="200"
            ms="uploadOnSave"
            output_file="$1.sftp1.txt";;
        8)
            echo -e "\e[31mSi Anjing memilih Pilihan Kedelapan\e[0m"
            dir_cari="/.vscode/sftp-config.json"
            respon="200"
            ms="uploadOnSave"
            output_file="$1.sftp2.txt"
            ;;
        9)
            echo -e "\e[31mSi Anjing memilih Pilihan Kesembilan\e[0m"
            dir_cari="/sftp.json"
            respon="200"
            ms="uploadOnSave"
            output_file="$1.sftp3.txt"
            ;;
        10)
            echo -e "\e[31mSi Anjing memilih Pilihan Kesepuluh\e[0m"
            dir_cari="/wp-content/plugins/essential-addons-for-elementor-lite/readme.txt"
            respon="200"
            ms="Stable tag:"
            output_file="$1.essentialWP.txt"
            ;;
        11)
            echo -e "\e[31mSi Anjing memilih Pilihan Kesebelas\e[0m"
            dir_cari="/jenkins/script"
            respon="200"
            ms="Script Console"
            output_file="$1.jenkins.txt"
            ;;
        12)
            echo -e "\e[31mSi Anjing memilih Pilihan Keduabelas\e[0m"
            dir_cari="/vendor/phpunit/phpunit/src/Util/PHP/"
            respon="200"
            ms="eval-stdin.php"
            output_file="$1.hg.txt"
            ;;
        13)
            echo -e "\e[31mSi Anjing memilih Pilihan Ketigabelas\e[0m"
            dir_cari="/wp-content/plugins/masterstudy-lms-learning-management-system/readme.txt"
            respon="200"
            ms="Stable tag:"
            output_file="$1.masterstudyWP.txt"
            ;;
        14)
            echo -e "\e[31mSi Anjing memilih Pilihan Keempatbelas\e[0m"
            dir_cari="/info.php"
            respon="200"
            ms="PHP Version"
            output_file="$1.phpinfo1.txt"
            ;;
        15)
            echo -e "\e[31mSi Anjing memilih Pilihan Kelimabelas\e[0m"
            dir_cari="/phpinfo.php"
            respon="200"
            ms="PHP Version"
            output_file="$1.phpinfo2.txt"
            ;;
        16)
            echo -e "\e[31mSi Anjing memilih Pilihan Keenambelas\e[0m"
            dir_cari="/phpinfo"
            respon="200"
            ms="PHP Version"
            output_file="$1.phpinfo3.txt"
            ;;
        17)
            echo -e "\e[31mSi Anjing memilih Pilihan Ketujuhbelas\e[0m"
            dir_cari="/assets/jquery-file-upload/"
            respon="200"
            ms="jQuery File Upload"
            output_file="$1.jquery-file-upload.txt"
            ;;
        18)
            echo -e "\e[31mSi Anjing memilih Pilihan Kedelapanbelas\e[0m"
            dir_cari="/wp-content/plugins/wp-fastest-cache/readme.txt"
            respon="200"
            ms="Stable tag:"
            output_file="$1.WP-Fastest-Cache.txt"
            ;;
        19)
            echo -e "\e[31mSi Anjing memilih Pilihan Kesembilanbelas\e[0m"
            dir_cari="/livewire/livewire.js"
            respon="200"
            ms="livewire"
            output_file="$1.liveware.txt"
            ;;
        *)
            echo -e "\e[31mPilihan tidak valid\e[0m"
            continue
            ;;
    esac

    # Jalankan httpx sesuai dengan opsi
    cat "$file_txt" | httpx404 -title -server -ip -path "$dir_cari" -fr -ms "$ms" -mc "$respon" -o "$output_file"
    echo -e "Hasil untuk \e[32mPilihan $choice\e[0m: \e[33m$output_file\e[0m"

    # Tunggu sebentar sebelum melanjutkan ke pilihan berikutnya
    sleep 2
done

echo -e "\e[31mSelesai menjalankan semua pilihan.\e[0m"