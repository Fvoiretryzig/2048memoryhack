#include <sys/ptrace.h>
#include <stdio.h>
#include <string.h>
#include <regex.h>
#include <assert.h>
#include <stdlib.h>

int pid;
int addr_start, addr_end;
int valid_addr[1024];
int valid_addr_cnt;
int edit_addr;
int num;
int edit_num;
int if_pause;
void pause()
{
	if_pause = 1;
	if(ptrace(PTRACE_ATTACH, (pid_t)pid, NULL, NULL) == -1){
		printf("\033[41;37merror when pause\033[0m\n");
		exit(1);
	}
	printf("\033[46;37mSuccessfully pause!\033[0m\n" );
	return;
}
void resume()
{
	if_pause = 0;
	if(ptrace(PTRACE_DETACH, (pid_t)pid, NULL, NULL) == -1){
		printf("\033[41;37merror when resume\033[0m\n");
		exit(1);
	}
	printf("\033[46;37mSuccessfully resume!\033[0m\n");
	return;
}
void lookup()
{
	int temp_addr[1024]; int temp_cnt = 0;
	int overlap[1024];	int overlap_cnt = 0;
	if(if_pause){
		for(int addr = addr_start; addr<addr_end; addr=addr+4){
			int data = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
			if(data == num){
				if(valid_addr_cnt == 0){
					valid_addr[temp_cnt++] = addr;
				}
				else{
					temp_addr[temp_cnt++] = addr;
				}
			}
		}
		if(valid_addr_cnt == 0){
			valid_addr_cnt = temp_cnt;
			return;
		}
		else{
			for(int i = 0; i<temp_cnt; i++){
				for(int j = 0; j<valid_addr_cnt; j++){
					if(temp_addr[i] == valid_addr[j]){
						overlap[overlap_cnt++] = temp_addr[i];
					}
				}		
			}
			if(overlap_cnt == 1){
				edit_addr = overlap[0];
				return;
			}
			else{
				for(int i = 0; i<valid_addr_cnt; i++){
					valid_addr[i] = 0;
				}
				for(int i = 0; i<overlap_cnt; i++){
					valid_addr[i] = overlap[i];
				}
				valid_addr_cnt = overlap_cnt;
			}
		}	
	}
	return;
}
void setup()
{
	if(if_pause){
		ptrace(PTRACE_POKEDATA, pid, edit_addr, edit_num);
	}
	return;
}
void init(char* pid_c)
{
	char* filename = NULL;
	strcpy(filename, "/proc/");
	strcat(filename, pid_c);
	strcat(filename, "/maps");
	FILE* fp = NULL;
	fp = fopen(filename, "r");
	
	regex_t data_seg;	
	char* pattern_data_seg = "[0-9,a-d]{8}-[0-9,a-d]{8} rw-p";
	/*int p_data_seg =*/ regcomp(&data_seg, pattern_data_seg, REG_EXTENDED);
	regmatch_t pm_data_seg[1];
	regex_t stop;
	char* pattern_stop = "[h,e,a,p]{4}]";
	/*int p_stop =*/ regcomp(&stop, pattern_stop, REG_EXTENDED);
	regmatch_t pm_stop[1];
	
	char* f_line = NULL;
	while (!feof(fp)) 
    {   
        if(fgets(f_line, 1024,fp)){
	        printf("%s", f_line);       
	        if(!regexec(&stop,f_line,1,pm_stop,0)){
	        	break;
	        }     
	        else{	//应该只会有一个数据段吧
	        	if(!regexec(&data_seg,f_line,1,pm_data_seg,0)){
					char* start = NULL; char* end = NULL;
					int point = 0;
					for(point = pm_data_seg[0].rm_so; point<pm_data_seg[0].rm_eo; point++){
						if(f_line[point] == '-'){
							point++;
							break;
						}
						start += f_line[point];
					}
					for(; point<pm_data_seg[0].rm_eo; point++){
						if(f_line[point] == ' ')
							break;
						end += f_line[point];
					}
					addr_start = atoi(start); addr_end = atoi(end);
	        	}
	        }  
	    } 
    regfree(&data_seg); regfree(&stop);	
	}
}
int main(int argc, char *argv[]) 
{
	printf("\033[42;37mline 140\033[0m\n");
	for (int i = 0; i < argc; i++) {
		assert(argv[i]); // specification
	}
	assert(!argv[argc]); // specification	
	if(argc == 1){
		printf("\033[41;37mError: Please enter the pid!\033[0m\n");
		exit(1);
	}
	char* pid_c = NULL;
	printf("\033[42;37mline 148\033[0m\n");
	strncpy(pid_c, argv[1], strlen(argv[1]));
	pid = atoi(pid_c);
	char cmd[15];
	init(pid_c);
	memset(valid_addr, 0, sizeof(valid_addr));
	valid_addr_cnt = 0;
	printf("\033[42;37mline 155\033[0m\n");
	while(fgets(cmd, sizeof(cmd), stdin)){
		printf("\033[42;31mhahaha\033[0m\n");
		if(!strcmp(cmd, "pause")){
			pause();
		}
		else if(!strcmp(cmd, "resume")){
			resume();
		}
		else if(strcmp(cmd, "lookup") > 0){
			char* temp = strtok(cmd, " ");
			temp = strtok(NULL, " ");
			num = atoi(temp);
			lookup();
		}
		else if(!strcmp(cmd, "setup")){
			char* temp = strtok(cmd, " ");
			temp = strtok(NULL, " ");
			edit_num = atoi(temp);
			setup();
		}
		else{
			printf("\033[41;37mInvalid command! Please enter again!\033[0m\n");
		}
		
	}	
	return 0;
}
