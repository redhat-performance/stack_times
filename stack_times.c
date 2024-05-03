#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>

struct stack_info {
	char *stack;
	long number_probes;
};

#define MAX_UNIQUE_STACKS 1000

struct stack_record {
	char *function;
	int depth;
	long long start_time;
	long long end_time;
};

struct time_calc {
	long long start_time;
	long long talley;
};


/*
 * To keep tthe size down.
 */
#define MAX_PASSES 128

struct stack_info stacks[MAX_UNIQUE_STACKS];
int number_stacks=0;

void
usage(char *exec_name)
{
	printf("%s Usage:\n", exec_name);
	printf("\t-c <command>: command to track\n");
	printf("\t-f <function>: function tracking\n");
	printf("\t-g: gather kernel profile data\n");
	printf("\t-k <kernel profile file>: File to save the kernel profile to/\n");
	printf("\t-p <profile file>: profile file to use\n");
	printf("\t-r <stack profilefile>: Generate timing stack based on what is in stack time profile file\n");
	printf("\t-s: number of stacks to show\n");
	printf("\t-u: this usage message\n");
	printf("To use tool\n");
	printf("1) ./stack_timings -c \"<command and args using>\" -g -k <kprofile out file>\n");
	printf("2) Determine what kernel function you want to track from.\n");
	printf("3a) If you want the trace regardless of command\n");
	printf("\t./stack_times  -f <func name> -p <kprofile out file from #1>\n");
	printf("3b) If you want to trace when executing a command. Note the program will execute the command for you\n");
	printf("\t./stack_times -c  \"command args\" -f <func name> -p <kprofile out file from #1>\n");
	printf("4) A file is produced stack_times_<func name> that containst the timing information.\n");
	printf("Files produced\n");
	printf("\tfunction_results: The results of hte bpftrace script gathering timing information\n");
	printf("\tfunction_track: The bpftrace script generated that gathers timing information\n");
	printf("\tkernel_profile.bt:  bpftrace script to gather general kernel profile (sampling)\n");
	printf("\tkprobes: list of bpftrace kprobes\n");
	printf("\tkprofile.out: kernel profile for the command executed.\n");
	printf("\tstack_times_<func name>: Time values for each function tracked in the stack\n");
	exit(0);
}

/*
 * Read in the records from the results file, and populate the data struture accordingly.
 */
void
populate_results(char *results_file, int *passes, struct stack_record **records_arg, FILE **fd_out, int *records_present)
{
	FILE *fd;
	char buffer[1024];
	char buffer1[1024];
	char *ptr, *ptr1;
	struct stack_record *records;
	int passes_present = 0;
	int rec_index;
	struct stack_record *rec_ptr;

	fd = fopen(results_file, "r");
	while (fgets(buffer, 1024, fd)) {
		if ( strstr(buffer, "Records:") ) {
			/*
			 * Retrieve the number of records we have.
			 */
			ptr = strchr(buffer, ':');
			ptr++;
			*records_present = atoi(ptr);
			records = (struct stack_record *) calloc(*records_present, sizeof(struct stack_record));
			*records_arg = records;
			continue;
		}
		if ( strstr(buffer, "@pass_index") ) {
			/*
			 * Figure out how many passes we have.
			 */
			if ( passes_present == MAX_PASSES ) {
				printf("Max passes encountered, reduce the number of passes.  Bailing\n");
				exit(1);
			}
			ptr = strchr(buffer, ':');
			ptr++;
			/*
			 * This tells us the end record number for the stack.
			 */
			passes[passes_present++] = atoi(ptr);
			continue;
		}
		if ( strstr(buffer, "@func[0]:") != NULL) {
			/*
			 * Get the top function.  We use this in the suffix for the final
			 * results file.
			 */
			ptr = strchr(buffer, '\n');
			ptr[0] = '\0';
			ptr = strchr(buffer, ' ');
			ptr++;
			sprintf(buffer1, "stack_times_%s", ptr);
			*fd_out = fopen(buffer1, "w");
		}
		/* Get rec index */
		ptr = strchr(buffer, '[');
		if ( ptr == NULL)
			continue;
		ptr++;
		/*
		 * Get the rec index.
		 */
		rec_index = atoi(ptr);
		rec_ptr = &records[rec_index];

		ptr = strchr(buffer, ':' );
		ptr++;
		if ( strstr(buffer, "@func[" )) {
			/*
			 * Function name.
			 */
			ptr1 = strchr(ptr, '\n');
			if ( ptr1 )
				ptr1[0] = '\0';
			ptr++;
			rec_ptr->function = strdup(ptr);
			continue;
		}
		if ( strstr(buffer, "@func_depth[" )) {
			/*
			 * Stack depth of this function.
			 */
			rec_ptr->depth = atoi(ptr);
			continue;
		}
		if ( strstr(buffer, "@func_start[" )) {
			/*
			 * Time this function started.
			 */
			rec_ptr->start_time = atoll(ptr);
			continue;
		}
		if ( strstr(buffer, "@func_end[" )) {
			/*
			 * Time this function ended.
			 */
			rec_ptr->end_time = atoll(ptr);
			continue;
		}
	}
	fclose(fd);
}

/*
 * Calculate the times of each function and report it to the user.
 */
void
calculate_and_report_times(int records_present, int *passes, struct stack_record *records, FILE *fd_out) 
{
	int *cur_pass;
	int depth;
	struct time_calc depth_times[30];
	struct stack_record *rec_ptr;
	long long time_period;
	long long start_period = 0, end_period;
	int count;
	long long time_mark;
	char buffer[1024];
	int add_tabs;

	cur_pass = &passes[0];

	for (count = 0; count < records_present; count++) {
		rec_ptr = &records[count];
		if ( *cur_pass == count ) {
			if (start_period != 0) {
				/* Give the total time for the stack. */
				fprintf(fd_out, "Total elpased ns: %lld\n", end_period - start_period);
			}
			start_period = rec_ptr->start_time;
			fprintf(fd_out, "======= New stack ===== \n");
			cur_pass++;
		}
		/*
		 * For each depth of the stack, print a tab.
		 */
		depth = rec_ptr->depth;
		for (add_tabs = 1; add_tabs < depth; add_tabs++)
			fprintf(fd_out, "\t");
		if ( rec_ptr->start_time ) {
			/*
			 * If this is a function entry, update the time.
			 */
			depth_times[depth].start_time = rec_ptr->start_time;
			depth_times[depth].talley = 0;
			/*
			 * Just the function name.
			 */
			fprintf(fd_out, "%s\n", rec_ptr->function);
		} else {
			/*
			 * If start time is NULL, then end time is set. Report the time used, do not forget
			 * to remove the time of all the sub functions.
			 */
			time_period = rec_ptr->end_time - depth_times[depth].start_time - depth_times[depth].talley;
			end_period = rec_ptr->end_time;
			depth_times[depth].start_time = 0;
			/*
			 * Update the the time talley if required.  Attribute this to the function above.
			 */
			if ( depth > 0) 
				depth_times[depth - 1].talley +=  depth_times[depth].talley+time_period;
			depth_times[depth].talley = 0;
			if (rec_ptr->function != NULL)
				fprintf(fd_out, "%-30s Elapsed ns: %ld\n", rec_ptr->function, time_period);
		}
	}
	/*
	 * Make sure to report the last stack time.
	 */
	fprintf(fd_out, "Total elpased ns: %lld\n", end_period - start_period);
}

/*
 * We have the results, calculate the times and generate a human readable output.
 */
static void
process_results(char *results_file)
{
	FILE *fd_out;
	struct stack_record *records;
	struct stack_record *rec_ptr;
	int records_present;
	int passes[MAX_PASSES];

	populate_results(results_file, passes, &records, &fd_out, &records_present);
	calculate_and_report_times(records_present, passes, records, fd_out);

	fclose(fd_out);
	exit(0);
}

static int
sort_stacks(const void *val1, const void *val2)
{
	struct stack_info *s1 = (struct stack_info *) val1;
	struct stack_info *s2 = (struct stack_info *) val2;
	return (strcmp(s1->stack, s2->stack));
}

static int
sort_probes(const void *val1, const void *val2)
{
	struct stack_info *s1 = (struct stack_info *) val1;
	struct stack_info *s2 = (struct stack_info *) val2;

	if (s1->number_probes > s2->number_probes)
		return(-1);
	if (s1->number_probes < s2->number_probes)
		return(1);
	return(0);
}

static int
locate_stack(const void *val1, const void *val2)
{
	char *s1 = (char *) val1;
	struct stack_info *s2 = (struct stack_info *) val2;

	return (strcmp(s1, s2->stack));
}

void
add_new_stack(long number_probes, char *stack)
{
	stacks[number_stacks].stack = stack;
	stacks[number_stacks].number_probes = number_probes;

	number_stacks++;
	if (number_stacks > 1) {
		qsort(stacks, number_stacks, sizeof(struct stack_info), sort_stacks);
	}
	return;
}

void
add_to_list(long number_probes, char *stack)
{
	struct stack_info *entry;
	if (number_stacks == 0) {
		add_new_stack(number_probes, stack);
		return;
	}
	entry = (struct stack_info *) bsearch(stack, stacks, number_stacks, sizeof(struct stack_info), locate_stack);
	if (entry != NULL) 
		entry->number_probes += number_probes;
	else
		add_new_stack(number_probes, stack);
}

/*
 * Given the output from the profile bpftrace script, build a list of stacks with
 * only the function names and the number of probes.
 */

void
process_stack(char *stack_file)
{
	FILE *fd;
	char buffer[1024];
	char stack[64][128];
	int stack_started = 0;
	char *ptr;
	long number_probes;
	int stack_index;
	int build_index;
	int count;

	fd = fopen(stack_file, "r");
	if (fd == NULL) {
		perror(stack_file);
		exit(1);
	}
	while(fgets(buffer, 1024, fd)) {
		if  (stack_started == 0) {
			if (buffer[0] == '@') {
				if (strstr(buffer, "[]")) {
					/*
					 * No stack reported
					 */
					continue;
				}
				stack_started=1;
				stack_index=0;
			}
			continue;
		}
		if (buffer[0] == ']') {
			/*
			 * End of stack, process.
			 */
			ptr=strchr(buffer,':');
			stack_started=0;
			if (ptr == NULL) {
				continue;
			}
			ptr++;
			number_probes = atol(ptr);
			/*
			 * Build the stack, we reverse the order so the entry is what we see first.
			 */
			ptr = (char *) calloc(1,8192);
			for (build_index = stack_index; build_index > 0; build_index--) {
		                if (ptr[0] != '\0')
                        		strcat(ptr, " ");
				strcat(ptr, stack[build_index - 1]);
			}
			add_to_list(number_probes, ptr);
			continue;
		}
		/*
		 * Add stack, ignore front matter.
		 */
		if (strstr(buffer, "do_syscall_64") || strstr(buffer, "entry_SYSCALL_64_after_hwframe"))
			continue;
		ptr = strchr(buffer, '+');
		ptr[0] = '\0';
		ptr = buffer;
		/* Remove all front white space. */
		while(isspace(ptr[0]))
			ptr++;
		strcpy(stack[stack_index++], ptr);
	}
	fclose(fd);
	/*
	 * Sort by probes.  This is done so we can track the top x stacks for the function
	 * tracing.
	 */
	qsort(stacks, number_stacks, sizeof(struct stack_info), sort_probes);
}


/*
 * Common center code for bpftrace probe entry.
 */
void
print_center_start_matter(FILE *fd, char *func)
{
	fprintf(fd, "\t$temp_depth = @depth;\n");
	fprintf(fd, "\t@tp = nsecs;\n");
	fprintf(fd, "\t$tp_temp = @tp;\n");
	fprintf(fd, "\t@func[@record] = \"%s\";\n", func);
	fprintf(fd, "\t@func_depth[@record] = $temp_depth;\n");
	fprintf(fd, "\t@func_start[@record] = $tp_temp;\n");
	fprintf(fd, "\t@func_end[@record] = 0;\n");
	fprintf(fd, "\t@record = @record + 1;\n");
	fprintf(fd, "}\n");
}

/*
 * Common center code for bpftrace probe return.
 */
void
print_center_end_matter(FILE *fd, char *function)
{
	fprintf(fd, "\t$temp_depth = @depth;\n");
	fprintf(fd, "\t@depth = @depth - 1;\n");
	fprintf(fd, "\t@tp = nsecs;\n");
	fprintf(fd, "\t$tp_temp = @tp;\n");
	fprintf(fd, "\t@func[@record] = \"%s\";\n", function);
	fprintf(fd, "\t@func_depth[@record] = $temp_depth;\n");
	fprintf(fd, "\t@func_start[@record] = 0;\n");
	fprintf(fd, "\t@func_end[@record] = $tp_temp;\n");
	fprintf(fd, "\t@record = @record + 1;\n");
	fprintf(fd, "}\n");

}

/*
 * bfpreace code for opening and closing function calls.
 */
void
add_func(FILE *fd, char *func)
{
	fprintf(fd, "kprobe:%s\n", func);
	fprintf(fd, "/ @track_it_tid == tid && @tracing_stack == 1 /\n");
	fprintf(fd, "{\n");
	fprintf(fd, "\t@depth = @depth + 1;\n");
	print_center_start_matter(fd, func);

	fprintf(fd, "kretprobe:%s\n", func);
	fprintf(fd, "/ @track_it_tid == tid && @tracing_stack == 1 /\n");
	fprintf(fd, "{\n");
	print_center_end_matter(fd, func);
}

/*
 * bpftrace code to execute when script is done.
 */
void
add_end_matter(FILE *fd)
{
	fprintf(fd, "END\n");
	fprintf(fd, "{\n");
	fprintf(fd, "\tprint(@pass_index);\n");
	fprintf(fd, "\tprintf(\"Records: %%d\\n\", @record);\n");
	fprintf(fd, "\tprintf(\"Function\\n\");\n");
	fprintf(fd, "\tprint(@func);\n");
	fprintf(fd, "\tprintf(\"Function depth\\n\");\n");
	fprintf(fd, "\tprint(@func_depth);\n");
	fprintf(fd, "\tprintf(\"Function start time\\n\");\n");
	fprintf(fd, "\tprint(@func_start);\n");
	fprintf(fd, "\tprintf(\"Function end time\\n\");\n");
	fprintf(fd, "\tprint(@func_end);\n");
	fprintf(fd, "\tclear(@pass_index);\n");
	fprintf(fd, "\tclear(@func);\n");
	fprintf(fd, "\tclear(@func_depth);\n");
	fprintf(fd, "\tclear(@func_start);\n");
	fprintf(fd, "\tclear(@func_end);\n");
	fprintf(fd, "\tclear(@track_it_tid);\n");
	fprintf(fd, "\tclear(@depth);\n");
	fprintf(fd, "\tclear(@passes);\n");
	fprintf(fd, "\tclear(@record);\n");
	fprintf(fd, "\tclear(@tracing_stack);\n");
	fprintf(fd, "\tclear(@tp);\n");
	fprintf(fd, "}\n");
}

/*
 * Sets up the bpftrace profile script, then invokes the script
 * followed by the command.  When the command exits, a signal 2
 * is sent to the bpftrace script to terminate it.
 */
void
gather_kernel_profile(char *command, char *res_file)
{
	FILE *fd;
	pid_t bpftrace;

	fd = fopen("kernel_profile.bt", "w");
	system("chmod 755 kernel_profile.bt");
	fprintf(fd, "#!/usr/bin/bpftrace\n");
	fprintf(fd, "profile:us:99\n{\n");
        fprintf(fd, "\t@a[kstack] = count();\n}\n");
	fclose(fd);

	bpftrace = fork();
	if (bpftrace == 0) {
		fclose(stdout);
		stdout = fopen(res_file, "w");
		execve("./kernel_profile.bt", NULL, NULL);
		exit(0);
	} else {
		/* Give it a chance */
		sleep(5);
		system(command);
		kill(bpftrace, 2);
	}
	exit(0);
}

/*
 * Given the command to execute and function tracking, we will
 * 1) Invoke the bpftrace stack time script.
 * 2) Invoke the command we are monitoring.
 * 3) When 2 completes, we signal the bpftrace script to end.
 *
 * When completed we have the raw data to generate the time stamps from.
 */
void
gather_stack_info(char *bpftrace_script, char *command, char *func)
{
	pid_t bpftrace;
	int status;

	bpftrace = fork();
	if (bpftrace == 0) {
		fclose(stdout);
		stdout = fopen("function_results", "w");
		execve(bpftrace_script, NULL, NULL);
		exit(0);
	} else {
		/* Give it a chance */
		if (command != NULL) {
			sleep(10);

			system(command);
			kill(bpftrace, 2);
			/*
		 	 * The bpftrace script can take a bit to actually complete.
		 	 */
		}
		waitpid(bpftrace, &status, 0);

	}
	/* Give it a chance */
	sleep(20);
	/*
	 * Generate the stack trace with time in each function.
	 */
	process_results("function_results");
}

/*
 * bpftrace standard information
 */
void
print_open_bpftrace_info(FILE *fd, char *function, char *command)
{
	/*
	 * Print out header.
	 */
	fprintf(fd, "#!/usr/bin/bpftrace\n\n");
	fprintf(fd, "BEGIN\n{\n\t@tracing_stack = 0;\n\t@record = 0;\n\t@passes = 0;\n\t@depth = 0;\n}\n\n");
	/*
	 * Print out start function.
	 */
	fprintf(fd, "kprobe:%s\n", function);
	if (command == NULL)
		fprintf(fd, "/ @tracing_stack == 0 /\n");
	else
		fprintf(fd, "/ @tracing_stack == 0  && comm == \"%s\" /\n", command);
	fprintf(fd, "{\n\tif (@passes == 20) {\n\t\texit();\n\t}\n");
	fprintf(fd, "\t@tracing_stack = 1;\n");
	fprintf(fd, "\t@pass_index[@passes] = @record;\n");
	fprintf(fd, "\t@passes = @passes +1;\n");
	fprintf(fd, "\t@track_it_tid = tid;\n");
	fprintf(fd, "\t@depth = 1;\n");
	print_center_start_matter(fd, function);

	/*
	 * print out end of start function
	 */
	fprintf(fd, "kretprobe:%s\n", function);
	fprintf(fd, "/ @track_it_tid == tid && @tracing_stack == 1 /\n");
	fprintf(fd, "{\n\t@tracing_stack = 0;\n");
	fprintf(fd, "\t@track_it_tid = 999999999;\n");
	print_center_end_matter(fd, function);
}

/*
 * Obtain the list of functions we are going to take time measurements on.
 */
void
obtain_kprobe_list(char *function, char *string_list)
{
	int count;
	char *ptr, *ptr1;
	char buffer[1024];
	int rtc;

	system("bpftrace -l | grep ^kprobe | cut -d':' -f 2 > kprobes");
	for (count = 0; count < number_stacks; count++) {
		if ((ptr = strstr(stacks[count].stack, function)) == NULL) {
			/* Not in the stack, skip */
			continue;
		}
		ptr = stacks[count].stack;
		ptr = strchr(ptr, ' ');
		while (ptr) {
			ptr1 = strchr(ptr, ' ');
			if (ptr1 != NULL) {
				ptr1[0] = '\0';
			}
			if (strcmp(ptr, "__schedule") == 0 || strcmp(ptr,"_raw_spin_lock") == 0  ||
			   strcmp(ptr, "_raw_spin_lock_irqsave") == 0 || strcmp(ptr, "_raw_spin_unlock_irqrestore") == 0) {
				if (ptr1 != NULL)
					ptr = ptr1 + 1;
				else
					ptr = NULL;
				continue;
			}
			/*
			 * Check to see if the function is valid.
			 */
			sprintf(buffer,"grep -q ^%s$ kprobes",ptr);
			rtc = system(buffer);
			if (rtc == 0) {
				/*
				 * Check for existing function
				 */
				if (string_list[0] != '\0') {
					if (strstr(string_list, ptr) == NULL) {
						strcat(string_list, " ");
						strcat(string_list, ptr);
					}
				} else 	{
					strcat(string_list, ptr);
				}
			}
			if (ptr1 != NULL)
				ptr = ptr1 + 1;
			else
				ptr = NULL;
		}
	}
}

/*
 *  We have the stack, now generate the time stack.
 */
void
generate_function_trace_script(char *command, char *function)
{
	char string_list[8192*2];
	FILE *fd;
	char *ptr, *cptr, *ptr1;
	char command_track[1024];
	int count;
	char buffer[1024];

	cptr = NULL;
	string_list[0] = '\0';

	if (command != NULL) {
		strcpy(command_track, command);
		ptr = strchr(command_track, ' ');
		if (ptr != NULL) {
			ptr[0] = '\0';
			cptr = strrchr(command_track, '/');
			if (cptr)
				cptr++;
			else
				cptr = command_track;
		} 
	}
	fd = fopen("function_track", "w");
	system("chmod 755 function_track");

	print_open_bpftrace_info(fd, function, cptr);

	/*
	 * Get the list of kprobes so we can see if the function we want is valid.
	 */
	obtain_kprobe_list(function, string_list);
	/*
	 * Add in for each function.
	 */
	ptr = string_list;
	while (ptr) {
		ptr1 = strchr(ptr, ' ');
		if (ptr1 != NULL)
			ptr1[0] = '\0';
		if (strcmp(ptr, function) != 0)  {
			add_func(fd, ptr);
		}
		if (ptr1 != NULL)
			ptr = ptr1 + 1;
		else
			ptr = NULL;
	}
	add_end_matter(fd);
	fclose(fd);
	gather_stack_info("./function_track", command, function);
	return;
}

int
main(int argc, char **argv)
{
	FILE *fd;
	char *ptr;
	int count;
	int opt;
	int stack_entries=1000;
	char buffer[1024];
	char *filename;
	char *function=NULL;
	char *command=NULL;
	char *kernel_profile = "kprofile.out";
	int gather_profile = 0;

	while ((opt = getopt(argc, argv, "k:f:p:uc:g")) != -1) {
		switch (opt) {
			case 'c':
				command=optarg;
			break;
			case 'f':
				function=optarg;
			break;
			case 'g':
				gather_profile = 1;
			break;
			case 'k':
				kernel_profile=optarg;
			break;
			case 'p':
				filename=optarg;
			break;
			case 's':
				stack_entries=atoi(optarg);
			break;
			case 'u':
				usage(argv[0]);
			break;
			default:
				usage(argv[0]);
			break;
		}
	}
	if ( gather_profile == 1 ) {
		/*
		 * Does not return.
		 */
		gather_kernel_profile(command, kernel_profile);
	}
	process_stack(filename);
	if (stack_entries > number_stacks)
		stack_entries = number_stacks;
	if  (function == NULL) {
		/*
		 * If we did not designate a function, simply dump the stacks.
		 */
		for (count = 0; count < stack_entries; count++) {
			printf("%ld %s\n", stacks[count].number_probes, stacks[count].stack);
		}
	} else {
		generate_function_trace_script(command, function);
	}
	return (0);
}
