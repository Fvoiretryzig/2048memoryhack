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
int hex_atoi(char* s)
{
	int len = strlen(s); int ans = 0;
	for(int i = len-1; i>=0; i--){
		int digital = 0; int pow_result = 1;
		if(s[i]>47 && s[i]<58){
			digital = s[i] - 48;
		}
		else if(s[i]>96 && s[i]<103){
			digital = s[i] - 87;
		}
		for(int j = 0; j<len-1-i; j++){
			pow_result *= 16;
		}
		ans += digital*pow_result;
	}
	return ans;
}
void init(char* pid_c)
{
	char filename[32];
	strcpy(filename, "/proc/");
	strcat(filename, pid_c);
	strcat(filename, "/maps");
	FILE* fp = NULL;
	fp = fopen(filename, "a+");
	while (!feof(fp)) 
    {   
		/*============data match============*/
		regex_t data_seg;	
		char* pattern_data_seg = "[0-9,a-d]{8}-[0-9,a-d]{8} rw-p";
		int p_data_seg = regcomp(&data_seg, pattern_data_seg, REG_EXTENDED);
		/*============stop match============*/
		regex_t stop;
		char* pattern_stop = "[h,e,a,p]{4}";
		int p_stop = regcomp(&stop, pattern_stop, REG_EXTENDED);
		/*============check============*/
		if(p_data_seg != 0 || p_stop != 0){
			printf("\033[46;37mError when compile regs\033[0m\n");
		}
		regmatch_t pm_data_seg[1];regmatch_t pm_stop[1];
	    char f_line[1024];
        if(fgets(f_line, 1024,fp)){
	        printf("%s\nlength:%d\n", f_line, strlen(f_line));  
	        f_line[strlen(f_line)-1] = '\0'; 
	        f_line[strlen(f_line)] = '\0';
	        f_line[strlen(f_line)+1] = '\0';
	        //printf("before stop match\n");
	        p_stop = regexec(&stop,f_line,1,pm_stop,0);
	        printf("\033[44;33mthis is stop ret:%d\033[0m\n", p_stop);
	        if(!p_stop){
	        	break;
	        }     
	        else{	//应该只会有一个数据段吧
	        	//printf("this is before regexec\n");
	        	p_data_seg = regexec(&data_seg,f_line,1,pm_data_seg,0);
	        	printf("\033[44;33mthis is data_seg ret:%d\033[0m\n", p_data_seg);
	        	if(!p_data_seg){
					char start[10]; char end[10];
					int point = 0;
					int start_p = 0; int end_p = 0;
					for(point = pm_data_seg[0].rm_so; point<pm_data_seg[0].rm_eo; point++){
						if(f_line[point] == '-'){
							point++;
							break;
						}
						start[start_p++] = f_line[point];
					}
					start[start_p] = '\0';
					for(; point<pm_data_seg[0].rm_eo; point++){
						if(f_line[point] == ' ')
							break;
						end[end_p++]= f_line[point];
					}
					end[end_p] = '\0';
					printf("\033[44;33mstart:%s end:%s\033[0m\n",start, end);
					addr_start = hex_atoi(start); addr_end = hex_atoi(end);
					printf("\033[44;33mstart:0x%08x end:0x%08x\033[0m\n",addr_start, addr_end);
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
		printf("argv[%d] = %s\n", i, argv[i]);
	}
	assert(!argv[argc]); // specification	
	if(argc == 1){
		printf("\033[41;37mError: Please enter the pid!\033[0m\n");
		exit(1);
	}
	char* pid_c = malloc(sizeof(*argv[1]));
	pid_c = argv[1];
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
