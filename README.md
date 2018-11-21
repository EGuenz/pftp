Eli Guenzburger

FTP Client Project

Creates N threads that all call execute_ftp. Each thread partioned a S/N chunk of file and a position to begin reading from (last thread may receive some extra bits <= S mod N) where S is file_size. Each call to execute_ftp also spawns another thread that creates socket connected to port returned by server, reads file sent by server and writes to file at its starting position. All threads can write to logfile, which is made thread_safe by a lock.  
