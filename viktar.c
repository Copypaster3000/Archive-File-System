//viktar.c
//Drake Wheeler
//CS333
//Lab 3

#include <stdio.h> 
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <md5.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include "viktar.h"

#define OPTIONS "xctTf:Vhv" //comand line options

#ifndef FALSE
# define FALSE 0
#endif // FALSE
#ifndef TRUE
# define TRUE 1
#endif // TRUE
#define BUF_SIZE 100

//used to print helpful debug statements
#ifdef NOISY_DEBUG
# define NOISY_DEBUG_PRINT fprintf(stderr, "%s %s %d\n", __FILE__, __func__, __LINE__)
#else // NOISY_DEBUG
# define NOISY_DEBUG_PRINT
#endif // NOISY_DEBUG
	   
int open_n_validate_archive(char* archive_name); //reads from stdin if necessary, opens and validates archive, returns file descriptor
void short_TOC(int fd, char* archive_file); //displays short table of contents
void long_TOC(int fd, char* archive_file); //displays short table of contents
void create_archive(char* archive_file, int archive_fd, int argc, char* argv[]); //create archive file
void convert_file_permission(mode_t, char* str); //converts the file permission from octal to human readable in a string
void extract_files(char* archive_file, int argc, char* argv[]); //exxtracts files from archive file
void validate_archive(int archive_fd, char* archive_file); //validates member files in an archive


int main(int argc, char* argv[])
{
	char* archive_file = NULL; //to store to name of the archive file	
	int fd = STDIN_FILENO; //input file descriptor
	int verbose_flag = FALSE; //to track if varbbose is enabled
	viktar_action_t action = ACTION_NONE; //To track -c -x -t -T -V command line options/ their actions


	{
		int opt = 0;

		NOISY_DEBUG_PRINT;
		while ((opt = getopt(argc, argv, OPTIONS)) != -1)
		{
			switch (opt)
			{
				case 'h':
					//print help message for the -h flag being passed in
					fprintf(stdout, "help text\n");
					fprintf(stdout, "\t./viktar\n");
					fprintf(stdout, "\tOptions: xctTf:Vhv\n");
					fprintf(stdout, "\t\t-x\t\textract file/files from archive\n");
					fprintf(stdout, "\t\t-c\t\tcreate an archive file\n");
					fprintf(stdout, "\t\t-t\t\tdisplay a short table of contents of the archive file\n");
					fprintf(stdout, "\t\t-T\t\tdisplay a long table of contents of the archive file\n");
					fprintf(stdout, "\t\tOnly one of xctTV can be specified\n");
					fprintf(stdout, "\t\t-f filename\tuse filename as the archive file\n");
					fprintf(stdout, "\t\t-V\t\tvalidate the MD5 values in the viktar file\n");
					fprintf(stdout, "\t\t-v\t\tgive verbose diagnostic messages\n");
					fprintf(stdout, "\t\t-h\t\tdisplay this AMAZING help message\n");

					exit(EXIT_SUCCESS); //exit program
					break;

				case 'v':
					verbose_flag = TRUE; //set ver_bose flag to true for 
					break;

				case 'f':
					archive_file = optarg;
					break;

				case 't':
					action = ACTION_TOC_SHORT;
				break;

				case 'x':
					action = ACTION_EXTRACT;
					break;

				case 'c':
					action = ACTION_CREATE;

					break;

				case 'T':
					action = ACTION_TOC_LONG;
					 
					break;

				case 'V':
					action = ACTION_VALIDATE;

					break;

				default:
					break;
			}
		}


	}

	//Print verbose message for -v flag
	if (verbose_flag) fprintf(stderr, "Verbose mode enabled\n");


	switch (action)
	{
		case ACTION_TOC_SHORT: //-t flag
			short_TOC(fd, archive_file); //dislay short table of contents 
			break;
		
		case ACTION_TOC_LONG: //-T flag
			long_TOC(fd, archive_file); //display long table of contents
			break;

		case ACTION_CREATE: //-c flag
			create_archive(archive_file, fd, argc, argv); //create archive file
			break;

		case ACTION_EXTRACT: //-x flag
			extract_files(archive_file, argc, argv); //extract member files from archive 
			break;

		case ACTION_VALIDATE: //-V flag
			validate_archive(fd, archive_file); 
			break;

		default:
			break;
	}

	return EXIT_SUCCESS;
}


//checks md5 data in the footer matches the actual archive member files
void validate_archive(int archive_fd, char* archive_file)
{
	viktar_header_t header; //to store the header of each member file
	viktar_footer_t footer; //to store the footer of each member file
	unsigned char buffer[BUF_SIZE] = {'\0'}; //to read data from archive
	int member_counter = 0; //to keep track of member files
	MD5_CTX md5_header_ctx, md5_data_ctx; //MD5 contexts for header and data
	uint8_t computed_md5_header[MD5_DIGEST_LENGTH]; //to store computed md5 checksum for header
	uint8_t computed_md5_data[MD5_DIGEST_LENGTH]; //to store computed md5 checksum for data
	ssize_t bytes_read = 0; //to store bytes read from read
	ssize_t footer_bytes_read = 0; //to store bytes read from footer
	ssize_t bytes_to_read = 0; //to store total bytes to read for current member file
	ssize_t bytes_read_data = 0; //
    int data_md5_match = 0;
	int header_md5_match = 0;

	//reads from stdin if archive_file is NULL, opens and validates archive file
	archive_fd = open_n_validate_archive(archive_file);
	
	//loop while there is still a header file to read int
    while ((bytes_read = read(archive_fd, &header, sizeof(viktar_header_t))) == sizeof(viktar_header_t))
    {
        ++member_counter; //increment the member counter

        //initialize MD5 context for header
        MD5Init(&md5_header_ctx);
        //update MD5 context with the header data
        MD5Update(&md5_header_ctx, (const uint8_t *)&header, sizeof(viktar_header_t));
        //finalize the MD5 checksum for the header
        MD5Final(computed_md5_header, &md5_header_ctx);

        //initialize MD5 context for data
        MD5Init(&md5_data_ctx);

        //read the data and compute MD5 checksum for the data
        bytes_to_read = header.st_size; // Total bytes to read for the current member

        while (bytes_to_read > 0)
        {
            //read data from the archive file, ensuring not to read more than what's left
            ssize_t chunk_size = (bytes_to_read < BUF_SIZE) ? bytes_to_read : BUF_SIZE;
            bytes_read_data = read(archive_fd, buffer, chunk_size);
            if (bytes_read_data <= 0)
            {
                fprintf(stderr, "Error reading archive data\n");
                close(archive_fd);
                exit(EXIT_FAILURE);
            }
            //update MD5 context with the data read
            MD5Update(&md5_data_ctx, buffer, bytes_read_data);
            bytes_to_read -= bytes_read_data; //decrement the bytes left to read
        }

        //finalize the MD5 checksum for the data
        MD5Final(computed_md5_data, &md5_data_ctx);

        //read the footer from the archive, which contains the stored MD5 checksums
        footer_bytes_read = read(archive_fd, &footer, sizeof(viktar_footer_t));
        if (footer_bytes_read != sizeof(viktar_footer_t))
        {
            fprintf(stderr, "Error reading footer\n");
            close(archive_fd);
            exit(EXIT_FAILURE);
        }


        //compare computed and stored MD5 checksums for header
        header_md5_match = memcmp(computed_md5_header, footer.md5sum_header, MD5_DIGEST_LENGTH) == 0;
        //compare computed and stored MD5 checksums for data
        data_md5_match = memcmp(computed_md5_data, footer.md5sum_data, MD5_DIGEST_LENGTH) == 0;

		printf("Validation for data member %d:\n", member_counter);

        if (!header_md5_match) printf("*** Header MD5 does not match:\n");
		else printf("\t\tHeader MD5 does match:\n");

		printf("    found:   ");
		for (int i = 0; i < MD5_DIGEST_LENGTH; ++i)
		{
			printf("%02x", computed_md5_header[i]);
		}
		printf("\n    in file: ");
		for (int i = 0; i < MD5_DIGEST_LENGTH; ++i)
		{
			printf("%02x", footer.md5sum_header[i]);
		}
		printf("\n");

        if (!data_md5_match) printf("*** Data MD5 does not match:\n");
		else printf("\t\tData MD5 does match:\n");

		printf("    found:   ");
		for (int i = 0; i < MD5_DIGEST_LENGTH; ++i)
		{
			printf("%02x", computed_md5_data[i]);
		}
		printf("\n    in file: ");
		for (int i = 0; i < MD5_DIGEST_LENGTH; ++i)
		{
			printf("%02x", footer.md5sum_data[i]);
		}
		printf("\n");

        //check for validation failure and report it
        if (!header_md5_match || !data_md5_match)
        {
            printf("*** Validation failure: %s for member %d\n", archive_file ? archive_file : "stdin", member_counter);
        }
    }

	//close fd if pointing to file
	if (archive_fd != STDOUT_FILENO) close(archive_fd);

	return;
}


//extracts files from archive file
void extract_files(char* archive_file, int argc, char* argv[])
{
	viktar_header_t header; //to store member files header data
	viktar_footer_t footer; //to store memebr file's footer data
	unsigned char buffer[BUF_SIZE] = {'\0'};
	int archive_fd = STDIN_FILENO; //file descriptor for the archive_file
	int extract_all = FALSE; //set to true if there are no arguments on command line after parsing option flags
	int extract_this = FALSE; 
	char file_name[VIKTAR_MAX_FILE_NAME_LEN + 1];
	char buf[BUF_SIZE] = {'\0'}; //signed buffer

	//read from stdin if archive file wasn't passed in with -f
	//then open the archive file and validate it's a proper viktar archive
	//archive_fd = open_n_validate_archive(archive_file);

	if (archive_file != NULL)
	{
		//fprintf(stderr, "reading archive file: %s\n", archive_file);
		archive_fd = open(archive_file, O_RDONLY);
	}
	else 
	{
		archive_file = "stdin";
		fprintf(stderr, "reading archive from stdin");
	}

	//read viktar tag
	read(archive_fd, buf, strlen(VIKTAR_TAG));

	//check if file starts with valid viktar tag to validate archive
	if (strncmp(buf, VIKTAR_TAG, strlen(VIKTAR_TAG)) != 0 )
	{
		fprintf(stderr, "not a viktar file: \"%s\"\n", archive_file);
		exit(EXIT_FAILURE);
	}

	//if optind is pointing at or greater than the total command line arguments, there are no member files on the command line
	if (optind >= argc) extract_all = TRUE;

	//loop through each member file in the archive file
	while (read(archive_fd, &header, sizeof(viktar_header_t)) > 0)
	{
		//extract file name
		memcpy(file_name, header.viktar_name, VIKTAR_MAX_FILE_NAME_LEN);
		file_name[VIKTAR_MAX_FILE_NAME_LEN] = '\0'; //ensure null termination

		extract_this = extract_all; //reset extract this to flase if not extracting all member files

		if (!extract_all) //if not extracting all member files
		{
			for (int i = optind; i < argc; ++i) //loop through each member file name given on the command line
			{
				//compare the current member file name with the command line member file name
				if (strcmp(file_name, argv[i]) == 0)
				{
					extract_this = TRUE; //if there's a match, set this member file to be extracted
					break; //break loop, no need to compare the rest of the command line member file names
				}
			}
		}

		//if this member should be extracted
		if (extract_this)
		{
			ssize_t bytes_to_read = header.st_size; //get total bytes of member file content
			ssize_t bytes_read = 0;
			int out_fd = 0;
			struct timespec times[2];
			unsigned char md5_result[MD5_DIGEST_LENGTH];
			MD5_CTX md5_ctx;
			MD5Init(&md5_ctx);


			//open the output file for writing the extracted member file, create it if it doesn't exist and truncate it if it does
			out_fd = open(file_name, O_WRONLY | O_CREAT | O_TRUNC, header.st_mode);

			if (out_fd < 0)
			{
				perror("Error creating output file");
				exit(EXIT_FAILURE);
			}

			//set exact permission as stored in the archive
			fchmod(out_fd, header.st_mode);

			//read content from member file in archive and write it to newly created extracted memeber file
			while ((bytes_read = read(archive_fd, buffer, (bytes_to_read < BUF_SIZE) ? bytes_to_read : BUF_SIZE)) > 0)
			{
				//write the data from the archive file to the output file
				write(out_fd, buffer, bytes_read);
				bytes_to_read -= bytes_read; //reduce remaining bytes to read
				MD5Update(&md5_ctx, buffer, bytes_read); //udpated md5 checksum with data read
			}

			//finalize the md5 checksum for the data read
			MD5Final(md5_result, &md5_ctx);

			//read the footer to move file pointer and get the stored md5 checksum data
			read(archive_fd, &footer, sizeof(viktar_footer_t));

			//validate MD5 checksum against the footer
            if (memcmp(md5_result, footer.md5sum_data, MD5_DIGEST_LENGTH) != 0)
            {
                fprintf(stdout, "Warning: MD5 checksum mismatch detected for file '%s'. The extracted file content may be corrupted or differ from the original version. Proceeding with extraction anyway.\n", header.viktar_name);
            }

			//restore the timestamps on the extracted file
			times[0] = header.st_atim;
            times[1] = header.st_mtim;
			futimens(out_fd, times); //set extracted file with original stime stamps

			close(out_fd); //close the extracted member files output file descriptor
		}
		else //if this archive member file shouldn't be extracted
		{
			//skip over the file content and footer to set file pointer to the start of the next member file header
			lseek(archive_fd, header.st_size + sizeof(viktar_footer_t), SEEK_CUR);
		}
	}

	//close fd if pointing to file
	if (archive_fd != STDOUT_FILENO) close(archive_fd);

	return;
}
			


//creates archive file
void create_archive(char* local_archive_file, int archive_fd, int argc, char* argv[])
{
	viktar_header_t header; //to hold member file header info
	viktar_footer_t footer; //to hold member file footer info
	struct stat file_stat; //to hold member file stats that will go into header and fotter
	unsigned char local_buf[BUF_SIZE] = {'\0'}; //buffer
	ssize_t local_bytes_read = 0; //
	MD5_CTX md5_header_context;
	uint8_t md5_header_digest[MD5_DIGEST_LENGTH];
	MD5_CTX md5_data_context;
    uint8_t md5_data_digest[MD5_DIGEST_LENGTH];
						
	//if archive file was passed in as a -f argument
	if (local_archive_file != NULL)
	{
		//temporarily set umask to 0 to ensure exact permissions
		mode_t old_umask = umask(0);

		archive_fd = open(local_archive_file, O_WRONLY | O_TRUNC | O_CREAT, 0644);

		//resotre original mask
		umask(old_umask);

		if (archive_fd < 0)
		{
			perror("Error creating file");
			exit(EXIT_FAILURE);
		}
	}
	else //if no archive file was passed in on the command line
	{
		archive_fd = STDOUT_FILENO; //set fd to stdout to write the archive to stdout
	}

	//either write to STDOUT_FILENO if archive file name to passed in, or write to archive file
	//write the viktar tag
	write(archive_fd, VIKTAR_TAG, strlen(VIKTAR_TAG));

	//add the member files to the archive
	//if there are command line args that aren't flags or required args, they are file members
	for (int i = optind; i < argc; ++i)
	{
		//open file in read only mode and set file descriptor
		int member_file_fd = open(argv[i], O_RDONLY);

		if (member_file_fd < 0) //check for successful file opening
		{
			perror("Error opening file");
			exit(EXIT_FAILURE);
		}

		//set header.viktar_name to the member file name
		strncpy(header.viktar_name, argv[i], VIKTAR_MAX_FILE_NAME_LEN);

		//get all the file stats from the member file and set them in the file_stat struct
		fstat(member_file_fd, &file_stat);
		//copy all file stat info into header struct
		header.st_size = file_stat.st_size;
		header.st_mode = file_stat.st_mode;
		header.st_uid = file_stat.st_uid;
		header.st_gid = file_stat.st_gid;
        header.st_atim = file_stat.st_atim;
        header.st_mtim = file_stat.st_mtim;


		//computer md5 for header
		MD5Init(&md5_header_context);
		MD5Update(&md5_header_context, (const uint8_t *)&header, sizeof(viktar_header_t));
		MD5Final(md5_header_digest, &md5_header_context);
		memcpy(footer.md5sum_header, md5_header_digest, MD5_DIGEST_LENGTH);

		//write member file header to archive file
		write(archive_fd, &header, sizeof(viktar_header_t));

		//compute md5 for file data
        MD5Init(&md5_data_context);

		//write file content to archive file and update md5 checksum
		while ((local_bytes_read = read(member_file_fd, local_buf, BUF_SIZE)) > 0)
		{
			write(archive_fd, local_buf, local_bytes_read);
			MD5Update(&md5_data_context, local_buf, local_bytes_read);
		}


		
		// Finalize the MD5 checksum for file data
        MD5Final(md5_data_digest, &md5_data_context);
        memcpy(footer.md5sum_data, md5_data_digest, MD5_DIGEST_LENGTH);


		//write member file footer to archive file
		write(archive_fd, &footer, sizeof(viktar_footer_t));

		//close member file
		close(member_file_fd);
	}

	//close fd if pointing to file
	if (archive_fd != STDOUT_FILENO) close(archive_fd);

	return;
}


//opens archive file name passed in with -f or reads from stdin and validates archive
int open_n_validate_archive(char* archive_name)
{
	int fd = STDIN_FILENO; //input file descriptor
	char buf[BUF_SIZE] = {'\0'}; //buffer


	//if archive file was set as a command line argument
	if (archive_name != NULL)
	{
		fprintf(stderr, "reading archive file: \"%s\"\n", archive_name);

		//open the file that's name is stored in archive_file in read only mode
		//store that files file descriptor in fd
		fd = open(archive_name, O_RDONLY);

		if (fd < 0) //if error opening file
		{
			fprintf(stderr, "Error: Cannot open %s for input\n", archive_name);
			exit(EXIT_FAILURE);
		}

	}
	else
	{
		fprintf(stderr, "reading archive from stdin\n");

		fd = STDIN_FILENO; //read archive data directly from stdin
		archive_name = "stdin";
	}

	//read viktar tag
	read(fd, buf, strlen(VIKTAR_TAG));

	//check if file starts with valid viktar tag to validate archive
	if (strncmp(buf, VIKTAR_TAG, strlen(VIKTAR_TAG)) != 0 )
	{
		fprintf(stderr, "not a viktar file: \"%s\"\n", archive_name);
		exit(EXIT_FAILURE);
	}

	return fd; //return file descriptor
}


//display short table of contents for -t flag
//pass in file descriptor
void short_TOC(int fd, char* archive_file)
{
	char buf[BUF_SIZE] = {'\0'}; //buffer
	viktar_header_t md; //viktar member file header struct of metadata for member files

	//reads from stdin if needed, opens and validates archive file, sets file descriptor
	fd = open_n_validate_archive(archive_file);

	//Print archive file name
	printf("Contents of viktar file: \"%s\"\n", archive_file != NULL ? archive_file : "stdin");

	//while it hasn't reached end of archive, it reads one viktar_header_t struct at a time from fd into md
	while (read(fd, &md, sizeof(viktar_header_t)) > 0)
	{
		memset(buf, 0, 100); //clears buffer
		//copies the .viktar_name struct data member from md into buf, max 22 characters
		strncpy(buf, md.viktar_name, VIKTAR_MAX_FILE_NAME_LEN);
		//print archive member file name
		printf("\tfile name: %s\n", buf);
		//moves file pointer forward by the size of the current file (md.st_size) plus the size of its footer (viktar_footer_t),
		//effectively skipping over the file's data and checksum to move to the start of the next member file.
		lseek(fd, md.st_size + sizeof(viktar_footer_t), SEEK_CUR);
	}

	//close fd if pointing to file
	if (fd != STDOUT_FILENO && !isatty(fd)) close(fd);

	return;
}


//displays long table of contents for -T flag
void long_TOC(int fd, char* archive_file)
{
	viktar_header_t md; //metadata for each memebr file in archive
	viktar_footer_t footer; //footer of MD5 info
	struct passwd* pw; //to hold user info
	struct group* gr; //to hold group info
	struct tm* mtime; //to store modificaiton time
	struct tm* atime; //to store access time
	char permission_str[BUF_SIZE] = {'\0'}; //to hold the member file permissions
	char time_str[BUF_SIZE] = {'\0'}; //to hold the formatted time string

	//reads from stdin if needed, opens and validates archive file, sets file descriptor
	fd = open_n_validate_archive(archive_file);
					
	//Print archive file name
	printf("Contents of viktar file: \"%s\"\n", archive_file != NULL ? archive_file : "stdin");

	//while haven't reached the end of archive, read the header into md
	while (read(fd, &md, sizeof(viktar_header_t)) > 0)
	{
		printf("\tfile name: %s\n", md.viktar_name);

		//convert the file permission from numbers to characters
		convert_file_permission(md.st_mode, permission_str);
		printf("\t\tmode:\t\t%s\n", permission_str);

		//set pw to struct with user info
		pw = getpwuid(md.st_uid);
		printf("\t\tuser:\t\t%s\n", pw ? pw->pw_name : "unknown");

		//set gr to struct with group info
		gr = getgrgid(md.st_gid);
		printf("\t\tgroup:\t\t%s\n", gr ? gr->gr_name : "unknown");
		printf("\t\tsize:\t\t%ld\n", md.st_size);

		//convert time in member file to local time
		mtime = localtime(&md.st_mtim.tv_sec);
		//formtat time into string
 		strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S %Z", mtime);
        printf("\t\tmtime:\t\t%s\n", time_str);

		//convert time in member file to local time
		atime = localtime(&md.st_atim.tv_sec);
		//format time into string
		strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S %Z", atime);
        printf("\t\tatime:\t\t%s\n", time_str);

		//skip over the file contents and move the file pointer to the beginning of the footer.
		lseek(fd, md.st_size, SEEK_CUR);

		//read from the footer into footer variable
		read(fd, &footer, sizeof(viktar_footer_t));

		
        printf("\t\tmd5 sum header:\t");
		//print each byte in the footer sum_header in hexidecimal
        for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) 
		{
            printf("%02x", footer.md5sum_header[i]);
        }
        printf("\n");

        printf("\t\tmd5 sum data:\t");
		//print each byte the the footer sum data in hexidecimal
        for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) 
		{
            printf("%02x", footer.md5sum_data[i]);
        }
        printf("\n");
	}

	//close fd if pointing to file
	if (fd != STDOUT_FILENO) close(fd);

	return;
}


//converts file permissions to string
void convert_file_permission(mode_t mode, char* str)
{
    //file type character conversion
    str[0] = (S_ISDIR(mode)) ? 'd' :        //directory
             (S_ISCHR(mode)) ? 'c' :        //character device
             (S_ISBLK(mode)) ? 'b' :        //block device
             (S_ISREG(mode)) ? '-' :        //regular file
             (S_ISFIFO(mode)) ? 'p' :       //named pipe (FIFO)
             (S_ISLNK(mode)) ? 'l' :        //symbolic link
             (S_ISSOCK(mode)) ? 's' : '?';  //socket or unknown type

    //user permissions conversion
    str[1] = (mode & S_IRUSR) ? 'r' : '-';
    str[2] = (mode & S_IWUSR) ? 'w' : '-';
    str[3] = (mode & S_IXUSR) ? 'x' : '-';

    //group permissions conversion
    str[4] = (mode & S_IRGRP) ? 'r' : '-';
    str[5] = (mode & S_IWGRP) ? 'w' : '-';
    str[6] = (mode & S_IXGRP) ? 'x' : '-';

    //others permissions
    str[7] = (mode & S_IROTH) ? 'r' : '-';
    str[8] = (mode & S_IWOTH) ? 'w' : '-';
    str[9] = (mode & S_IXOTH) ? 'x' : '-';

    //null terminate the string
    str[10] = '\0';

	return;
}
