#2021/12/03 - enky_backup_checksum.py
# Script leverages 7z to do perform backups. It can also compute and check file sha256 hashes to detect file corruption.
# Uses python 3
# Note : when specifying the paths, do not use a final \ if it's within quotes or escape it \\
# depends on texttable (pip install texttable) and 7zip
# 
# Configure the encyrption key @ line 20 and edit the path to 7z.exe @ line 22 if required

import os
import hashlib
from datetime import datetime
import json
import argparse
import sys
import subprocess
import shutil
import texttable

#The encryption key (edit this)
password_7z = 'pass word@'
#point to 7zip and check if it exists (edit this)
path_7z = 'C:/Program Files/7-Zip/7z.exe'

#Get all the files inside target. Pathnames are absolute. Doesn't add escape sequence to spaces
def get_target_tree (target_directory):
	file_list = []
	for root, dirs, filenames in os.walk (target_directory, topdown=False):
		for filename in filenames:
			fqn_path = os.path.join(root, filename)
			file_list.append(fqn_path)
	return file_list

#hashing function (64K chunk seems to be same speed as 7z hash). Windows handles the file caching and buffering.
def hash_file(filename):
   # make a hash object
   h = hashlib.sha256()

   # open file for reading in binary mode
   with open(filename,'rb') as file:

       # loop till the end of the file
       chunk = 0
       while chunk != b'':
           # read only 1024 bytes at a time
           #chunk = file.read(4096)
           chunk = file.read(65536)
           h.update(chunk)

   # return the hex representation of digest
   return h.hexdigest()

#recursively computes hashes of all files in a path. Returns a list of [file, hash]
def hash_files_in_path (path):
	row_list = []
	row_line = []
	file_list = get_target_tree (path)

	file_count = len (file_list)

	print ("Found {0} files in path".format(file_count) )

	for i,file in enumerate(file_list):
		print ("Hashing {0} of {1} ({2:.1f}%)".format(i + 1, file_count, (i*100/file_count)), end='\r')
		hash_value = hash_file(file)
		row_list.append ([file,hash_value])
	return row_list

#recursively checks the hash of files in path (only the ones from the hash list). Checks for deletions and mismatches
def verify_hashes_in_path (path, hash_list):
	count_delete = 0
	count_mismatch = 0
	if (os.path.isdir(path)):
		for line in hash_list:
			if (os.path.isfile (line[0])):
				computed_hash = hash_file(line[0])
				if (computed_hash != line[1]):
					print ("[mismatch] "+ line[0] )
					count_mismatch += 1
			else:
				print ("[deleted] " + line[0] )
				count_delete += 1
		if ((count_delete == 0 ) and ( count_mismatch == 0) ):
			print ("[no discrepancies found]")
	else:
		print ("Error : (hash verify) invalid target path")

#saves data to file as a json. Appends a signature to id the file
def save_hashes_to_file (filename, hashlist, target_directory):
	print ("saving hashes to file : " + filename)
	with open (filename, "w") as fh_dump:
		json.dump(["This is a enky hash list", hashlist,  target_directory], fh_dump)
		
#retrieve data from file as a json
def load_hashes_from_file (filename):
	if (os.path.isfile(filename)):
		print ("Loading hash file")
		with open (filename, "r") as fh_dump:
			data = json.load(fh_dump)
		if (data[0] == "This is a enky hash list"):
			print ("Info : File matches Enky signature, loading hashes and target directory")
			return data
		else:
			print ("Error: Invalid input hash list!")
	else:
		print ("Error: File not found!")

def display_error():
	print ("Enky doesn't undersand what you want to do.")
	print ("Please run :" + __file__ + " -h\n")
	sys.exit()

def process_checksum_mode(param_list):
	#are we checking the hash?
	if (param_list.hashcheck == True):
		print ("==>hash check mode\n")
		#in hash check the hashfile is mandatory, hashtarget is optional
		if (param_list.hashfile == None):
			print ("Error! Please specify the hashfile (-hf)")
			display_error()

		#load up the hash information
		hash_data = load_hashes_from_file(param_list.hashfile)

		#override the target directory on which hash check should be done.
		if (param_list.hashtarget != None):
			if (os.path.isdir(param_list.hashtarget)):
				print ("Info : Verifying hashes for files in ({0}) against hashfile ({1})\n".format (param_list.hashtarget, param_list.hashfile) )
				verify_hashes_in_path(param_list.hashtarget,hash_data[1])
			else:
				print ("Error! Can't access the directory to verify ({0})".format(param_list.hashtarget) )
				display_error()
		
		#call the check function with the stored path
		else:
			print ("Info : Verifying hashes for files in ({0}) against hashfile ({1})\n".format (hash_data[2], param_list.hashfile) )
			verify_hashes_in_path(hash_data[2],hash_data[1])
		print ("")

	#if we are creating the hash
	elif (param_list.hashstore == True):
		print ("==>hash store mode\n")
		if (param_list.hashtarget == None):
			print ("Please specify a directory that needs to be hashed (hashtarget)")
			display_error()
		if (param_list.hashfile == None):
			print ("Please specify a file to save the hashlist in (hashfile)")
			display_error()
		if ( os.path.isdir(param_list.hashtarget) ):
			print ("Info : Generating hashes for files in ({0}) and storing data in ({1})".format (param_list.hashtarget, param_list.hashfile) )
			hash_data = hash_files_in_path(param_list.hashtarget)
		else:
			print ("Error: Can't access the directory with the files to hash (hashtarget = {0})".format (param_list.hashtarget) )
			display_error()

		save_hashes_to_file(param_list.hashfile, hash_data, param_list.hashtarget)
	else:
		print ("Error: Please specify hash operation (check : -hc) or (store : -hs)")
		display_error()

def check_if_archive_present (file):
	if (os.path.isfile(file) == False):
		print ("Error! unable to find backup archive : " + file)
		sys.exit()			

#returns a file size string (just for aesthetics, not calculations)
def get_file_size_string (file):
	if (os.path.isfile(file)):
		f_size = os.path.getsize(file)
	else:
		print ("Error! (internal) can't open file ", file)
		sys.exit()

	if (f_size < 1024):
		return str(f_size)+"B"
	elif (f_size < 1048576):
		return str(f_size/1024)+"KiB"
	elif (f_size < 1073741824):
		return str(f_size/1024/1024)+"MiB"
	elif (f_size < 1099511627776):
		return str(f_size/1024/1024/1024)+"GiB"
	else:
		return str(f_size/1024/1024/1024/1024)+"TiB"

def process_backup_mode(param_list):
	#encryption password(tested with spaces, ' and @. Avoid ")
	fullbackup_filename = 'fullback.7z'

	now = datetime.now()
	current_date = now.strftime("%Y/%m/%d %H:%M")


	if (os.path.isfile(path_7z) == False):
		print ("Error! Can't find 7zip. Please ensure that it's installed and the path within the script is correct. Need this software for creating/restoring backups.")
		sys.exit()
	
	#7zip commands
	cmd7z_fullbackup = [path_7z, 'u', "target_zip_2", "source_dir_3", '-up0q0r2x2y2z1w2', '-mmt4', '-mx2', '-p'+password_7z, '-mhe']

	#print (cmd7z_fullbackup)

	manifest_filename = "enky_backup_manifest.json"

	#do we want to list the backups?
	if (param_list.backupview == True):
		print ("==>backup(s) view mode\n")
		#check for retarded backup options
		if (param_list.backupcreate == True):
			print ("Error! backup view (-bv) and backup create (-bc) are incompatible")
			sys.exit()
		if (param_list.backuprestore == True):
			print ("Error! backup view (-bv) and backup restore (-br) are incompatible")
			sys.exit()

		#check if files and paths exist
		if (os.path.isdir(param_list.backuplocation) == False):
			print ("Error! unable to access the backup location (-bl ", param_list.backuplocation, " )")
			sys.exit()

		manifest_file = os.path.join(param_list.backuplocation, manifest_filename) 
		
		#check if the backup manifest exists
		if (os.path.isfile(manifest_file) == False):
			print ("Error! Couldn't fine a backup manifest at the backuplocation (-bl ", param_list.backuplocation, " )")
			print (" The backup might have been lost or corrupted")
			sys.exit()

		#load up the manifest
		with open (manifest_file, "r") as fh_dump:
			manifest_data = json.load(fh_dump)
		fh_dump.close()

		print ("Info: loaded backup manifest")
		if (manifest_data[-1][4] == 'diff'):
			print ("Info: differential backup detected")
		elif (manifest_data[0][4] == 'inc'):
			print ("Info: Incremental backup detected")
		else:
			print ("Info: Full backup detected")

		if (param_list.backupprettyview == False):
			#parse through the list of backups
			print ("sl.no\t\tdate\tsize\tcomments")
			#print ("=====================")
			for item in manifest_data:
				slno = item[0] + 1
				date = item[2]
				bcomment = item[3]
				bfpath = os.path.join(param_list.backuplocation, item[1])
				bsize = get_file_size_string(bfpath)
				print ("{0})\t{1}\t{2}\t{3}".format (slno, date, bsize, bcomment))
		else:
			data_table = [["sl.no", "date", "size", "comments"]]
			print ("")
			for item in manifest_data:
				slno = item[0] + 1
				date = item[2]
				bcomment = item[3]
				bfpath = os.path.join(param_list.backuplocation, item[1])
				bsize = get_file_size_string(bfpath)
				data_table.append([slno, date, bsize, bcomment])
			t = texttable.Texttable()
			t.add_rows(data_table)
			print(t.draw())

	#do we want to check the integrity of the backups?
	elif (param_list.backupcheckintegrity == True):
		print ("==>backup(s) view mode\n")
		#check for retarded backup options
		if (param_list.backupcreate == True):
			print ("Error! backup check integrity (-bci) and backup create (-bc) are incompatible")
			sys.exit()
		if (param_list.backuprestore == True):
			print ("Error! backup check integrity (-bci) and backup restore (-br) are incompatible")
			sys.exit()

		#check if files and paths exist
		if (os.path.isdir(param_list.backuplocation) == False):
			print ("Error! unable to access the backup location (-bl ", param_list.backuplocation, " )")
			sys.exit()

		manifest_file = os.path.join(param_list.backuplocation, manifest_filename) 
		
		#check if the backup manifest exists
		if (os.path.isfile(manifest_file) == False):
			print ("Error! Couldn't fine a backup manifest at the backuplocation (-bl ", param_list.backuplocation, " )")
			print (" The backup might have been lost or corrupted")
			sys.exit()

		#load up the manifest
		with open (manifest_file, "r") as fh_dump:
			manifest_data = json.load(fh_dump)
		fh_dump.close()

		print ("Info: loaded backup manifest")
		if (manifest_data[-1][4] == 'diff'):
			print ("Info: differential backup detected")
		elif (manifest_data[0][4] == 'inc'):
			print ("Info: Incremental backup detected")
		else:
			print ("Info: Full backup detected")

		#run a 7z test on all the parts in the backup, get the integrity result and tabulate
		cmd7z_checkbackup = [path_7z, "t", "path_to_7z_2", '-p'+password_7z]
		integrity_check_results = []

		#check integrity
		for item in manifest_data:
			temp_full_path = os.path.join(param_list.backuplocation, item[1])
			cmd7z_checkbackup[2] = temp_full_path
			if (os.path.isfile(temp_full_path) == False):
				integrity_check_results.append("MIS")
			else:
				try:
					check_results = subprocess.check_output(cmd7z_checkbackup)				
				except subprocess.CalledProcessError:
					print ("Exception! failed to run the 7z command : ")
					print (cmd7z_checkbackup)
					sys.exit()
				if (b'Everything is Ok' in check_results):
					integrity_check_results.append("OK")
				else:
					integrity_check_results.append("BAD")


		if (param_list.backupprettyview == False):
			#parse through the list of backups
			print ("sl.no\t\tdate\tarchive\tIntegrity")
			#print ("=====================")
			for i, item in enumerate(manifest_data):
				slno = item[0] + 1
				date = item[2]
				bcomment = item[3]
				bfpath = os.path.join(param_list.backuplocation, item[1])				
				print ("{0})\t{1}\t{2}\t{3}".format (slno, date, item[1], integrity_check_results[i]))
		else:
			data_table = [["sl.no", "date", "archive", "Integrity"]]
			print ("")
			for i, item in enumerate(manifest_data):
				slno = item[0] + 1
				date = item[2]
				bcomment = item[3]
				bfpath = os.path.join(param_list.backuplocation, item[1])
				data_table.append([slno, date, item[1], integrity_check_results[i] ])
			t = texttable.Texttable()
			t.add_rows(data_table)
			print(t.draw())

	#do we want to restore a backup?
	elif (param_list.backuprestore == True):
		print ("==>backup restore mode\n")
		#check for retarded backup options
		if (param_list.backupcreate == True):
			print ("Error! backup restore (-br) and backup create (-bc) are incompatible")
			sys.exit()

		#check if files and paths exist
		if (os.path.isdir(param_list.backuplocation) == False):
			print ("Error! unable to access the backup location (-bl ", param_list.backuplocation, " )")
			sys.exit()

		manifest_file = os.path.join(param_list.backuplocation, manifest_filename) 
		
		#check if the backup manifest exists
		if (os.path.isfile(manifest_file) == False):
			print ("Error! Couldn't fine a backup manifest at the backuplocation (-bl ", param_list.backuplocation, " )")
			print (" The backup might have been lost or corrupted")
			sys.exit()

		#load up the manifest
		with open (manifest_file, "r") as fh_dump:
			manifest_data = json.load(fh_dump)
		fh_dump.close()

		print ("Info: loaded backup manifest")
		
		backup_index = -1 #just flags as uninitialized
		
		if (param_list.backuprestorenumber == None):					
			#for full backup, the index is kind of redundant. 
			if ( (manifest_data[-1][4] != 'diff') and (manifest_data[0][4] != 'inc')):
				print ("Info: (-brn) missing. Found a single full-backup, assuming restore point 1")
				backup_index = 0
			else:
				print ("Error! please select a backup to restore using the (-brn #number) switch")
				sys.exit()

		#check for invalid restore numbers
		if ( (param_list.backuprestorenumber < 1) or (param_list.backuprestorenumber > (manifest_data[-1][0] + 1) )  ):
			print ("Error! backup restore point selection invalid")
			print ("Please use a value in range : 1 to {0}".format(manifest_data[-1][0] + 1) )
			sys.exit()

		#if the backup index was uninitialized
		if (backup_index == -1):
			backup_index = param_list.backuprestorenumber - 1 #view index starts from 1, real index starts at 0

		#command for extracting out of the archive
		cmd7z_restore = [path_7z, "x", "-y","backuparchive_3", "output_dir_4", '-p'+password_7z]

		#for differential backup, restore the full backup and the single diff backup
		if (manifest_data[-1][4] == 'diff'):
			print ("Info: differential backup detected")
			temp_archive_file = os.path.join(param_list.backuplocation, manifest_data[0][1])
			cmd7z_restore[3] = temp_archive_file
			cmd7z_restore[4] = "-o" + param_list.backuptarget
			check_if_archive_present(cmd7z_restore[3])

			cmd7z_restorediff = cmd7z_restore.copy()
			cmd7z_restorediff[3] = os.path.join(param_list.backuplocation, manifest_data[backup_index][1])
			check_if_archive_present(cmd7z_restorediff[3])

			try:
				print ("Info : restoring base (full) backkup")
				subprocess.check_call(cmd7z_restore, stdout=subprocess.DEVNULL)
				print ("Info : restoring backup point ({0})".format(param_list.backuprestorenumber) )
				subprocess.check_call(cmd7z_restorediff, stdout=subprocess.DEVNULL)
			except subprocess.CalledProcessError:
				print ("Exception! failed to run the 7z command : ")
				print (cmd7z_restore)
				sys.exit()

		#for incremental backup, restore the full backup and everything to and including the selected inc backup
		elif (manifest_data[0][4] == 'inc'):
			print ("Info: Incremental backup detected")
			#cmd7z_restore[3] = os.path.join(param_list.backuplocation, manifest_data[-1][1])
			cmd7z_restore[4] = "-o" + param_list.backuptarget
			cmd7z_restoreinc = []

			#generate the commands list for every archive from full to the selected restore point
			for i in range (manifest_data[-1][0], backup_index - 1, -1):
				temp_cmd = cmd7z_restore.copy()
				temp_cmd[3] = os.path.join(param_list.backuplocation, manifest_data[i][1])
				check_if_archive_present(temp_cmd[3])
				cmd7z_restoreinc.append(temp_cmd)

			#extract all relevant archives
			try:
				for i, cmd_item in enumerate (cmd7z_restoreinc):
					last_cmd = cmd_item
					print ("Info : restoring incremental backup shard ({0})".format(manifest_data[-1][0] - i + 1) )
					subprocess.check_call(cmd_item, stdout=subprocess.DEVNULL)
			except subprocess.CalledProcessError:
				print ("Exception! failed to run the 7z command : ")
				print (last_cmd)
				sys.exit()


		#for a full backup, it'd be just a single file
		else:
			print ("Info: Full backup detected")
			temp_archive_file = os.path.join(param_list.backuplocation, manifest_data[0][1])
			cmd7z_restore[3] = temp_archive_file
			cmd7z_restore[4] = "-o" + param_list.backuptarget
			check_if_archive_present(cmd7z_restore[3])

			try:
				subprocess.check_call(cmd7z_restore, stdout=subprocess.DEVNULL)
			except subprocess.CalledProcessError:
				print ("Exception! failed to run the 7z command : ")
				print (cmd7z_restore)
				sys.exit()

		print ("Info: restored backup to : "+ param_list.backuptarget)
		print ("")


	#check if we want to create a backup
	elif (param_list.backupcreate == True):
		print ("==>backup creation mode\n")
		if (param_list.backuplocation == None):
			print ("Error: Please specify a location to store the backups (-bl)")
			display_error()
		if (param_list.backuptarget == None):
			print ("Error: Please specify the location (backuptarget) that needs to be backed up (-bt)")
			display_error()

		if ( os.path.isdir(param_list.backuptarget) == False):
			print ("Error: Can't access the backup target directory ({0})".format(param_list.backuptarget))
			display_error()

		if ( os.path.isdir(param_list.backuplocation) == False):
			print ("Info: creating backup storage location ({0})".format(param_list.backuplocation) )
			os.mkdir(param_list.backuplocation)

		#get full path to manifest file
		manifest_file = os.path.join(param_list.backuplocation, manifest_filename) 
		#get the full path to the full backup 7z archive
		fullbackup_file = os.path.join(param_list.backuplocation, fullbackup_filename)
		fullbackup_copy = os.path.join(param_list.backuplocation, "original_fullbackup.7z")

		# during incremental backup, the full backup gets updated. To prevent data loss, a copy is made first.
		#if the copy is found, the previous backup was interruptted. So, restore the copy. i.e. previous backup increment failed
		#but the rest is safe.
		if (os.path.isfile(fullbackup_copy)):
			print ("Warning! the last incremental backup was interrupted")
			print ("Rolling back to the last known good backup")
			if (os.path.isfile(fullbackup_file)):
				os.remove(fullbackup_file)
			os.rename(fullbackup_copy, fullbackup_file)


		#creating a full backup. The backup location can contain only one backup set.
		if (param_list.backupfull == True):
			
			#don't create a full backup into an existing backup path (that's a mess)
			if ( os.path.isfile (manifest_file) ):
				print ("Error! The backup location contains an existing backup. Will not perform a full backup into it to prevent data loss")
				print ("  Either specify a new backup location (-bl) or clear it up.")
				sys.exit()
			

			#initialize the manifest data
			manifest_data = [0, fullbackup_filename, current_date, param_list.backupname, 'full']
			cmd7z_fullbackup = [path_7z, 'u', fullbackup_file, param_list.backuptarget + "/\*", '-up0q0r2x2y2z1w2', '-mmt4', '-mx2', '-p'+password_7z, '-mhe']
			#print (cmd7z_fullbackup)
			#subprocess.run
			print ("Info : Starting full backup")
			try:
				subprocess.check_call(cmd7z_fullbackup, stdout=subprocess.DEVNULL)
			except subprocess.CalledProcessError:
				print ("Exception! failed to run the 7z command : ")
				print (cmd7z_fullbackup)
			print ("Info : Backup completed")
			with open (manifest_file, "w") as fh_dump:
				json.dump([manifest_data], fh_dump)
			print ("Info : Manifest written to file")

		#creating a differential backup
		elif (param_list.backupdifferential == True):			
			#check if there is a full backup in the location
			if ( (os.path.isfile (manifest_file) == True) and (os.path.isfile(fullbackup_file) == True) ):
				with open (manifest_file, "r") as fh_dump:
					manifest_data = json.load(fh_dump)
				fh_dump.close()
				
				if (manifest_data[0][4] == 'inc'):
					print ("Error: The backup at location is incremental. Can't peform a differential backup!")
					sys.exit()

				#add a new diff entry
				new_manifest_data = manifest_data[-1].copy()
				new_manifest_data[0] = new_manifest_data[0] + 1
				new_manifest_data[1] = "diff_part"+str(new_manifest_data[0])+".7z"
				new_manifest_data[2] = current_date
				new_manifest_data[3] = param_list.backupname
				new_manifest_data[4] = 'diff'
				manifest_data.append(new_manifest_data)

				diff_7z_path = os.path.join(param_list.backuplocation, new_manifest_data[1])
				cmd7z_diffbackup = [path_7z, 'u', fullbackup_file, '-u-', "-up0q3r2x2y2z0w2!"+diff_7z_path, param_list.backuptarget+ "/\*",  '-mmt4', '-mx2', '-p'+password_7z, '-mhe']

				#subprocess.run
				print ("Info : Starting differential backup")
				try:
					subprocess.check_call(cmd7z_diffbackup, stdout=subprocess.DEVNULL)
				except subprocess.CalledProcessError:
					print ("Exception! failed to run the 7z command : ")
					print (cmd7z_diffbackup)
					sys.exit()

				print ("Info : Backup completed")
				with open (manifest_file, "w") as fh_dump:
					json.dump(manifest_data, fh_dump)
				print ("Info : Manifest written to file")

			else:
				print ("Error: Please do a full backup prior to performing a differential one")
				sys.exit()

		#creating an incremental backup
		elif (param_list.backupincremental == True):
			#check if there is a full backup in the location
			if ( (os.path.isfile (manifest_file) == True) and (os.path.isfile(fullbackup_file) == True) ):
				with open (manifest_file, "r") as fh_dump:
					manifest_data = json.load(fh_dump)
				fh_dump.close()
				
				if (manifest_data[-1][4] == 'diff'):
					print ("Error: The backup at location is differential. Can't peform an incremental backup!")
					sys.exit()

				#add a new inc entry (inc mode, the full backup is the most recent one. )
				#keep the full backup as the top item. Unlike with diff, this keeps getting updated	[don't do this]
				#incremental backups flow downwards. The most oldest being at the end (so adding to end wont work)
				#
				#The last item will be a full backup. The first one could be an inc backup
				#append a new entry
				# replace the old entry with the inc backup. Date remains the same.
				# new entry will be a new full backup with current date.
				# topmost would be the oldest inc backup
				# 
				#One issue with this is that full backup keeps getting replaced. So an interruption could mess up an existing backup
				#use a temporary inc and full backup. Once it's done, remove the old one and rename
				new_manifest_data = manifest_data[-1].copy()
				new_manifest_data[0] = new_manifest_data[0] + 1
				manifest_data[-1][1] = "inc_part"+str(new_manifest_data[0])+".7z" #The inc backup rep the delta to get the older copy
				new_manifest_data[2] = current_date
				new_manifest_data[3] = param_list.backupname
				manifest_data[-1][4] = 'inc'

				int_7z_path = os.path.join(param_list.backuplocation, manifest_data[-1][1])
				manifest_data.append(new_manifest_data)

						
				cmd7z_intbackup = [path_7z, 'u', fullbackup_file, '-u-', "-up1q1r3x1y1z0w1!"+int_7z_path, param_list.backuptarget + "/\*",  '-mmt4', '-mx2', '-p'+password_7z, '-mhe']
				cmd7z_fullbackup =[path_7z, 'u', fullbackup_file, param_list.backuptarget + "/\*", '-up0q0r2x2y2z1w2', '-mmt4', '-mx2', '-p'+password_7z, '-mhe']
				print ("Info : Starting incremental backup")
				try:
					#make an incremental backup using existing full backup and backup target. It records the difference in full compared to target.
					if (os.path.isfile(int_7z_path) ):
						print ("Warning: Found a stale incremental archive (likely from a failed previous run). Removing it.")
						os.remove(int_7z_path)
					subprocess.check_call(cmd7z_intbackup, stdout=subprocess.DEVNULL)
					#make a copy of the existing full backup. Prevents data loss if the update gets interrupted
					shutil.copyfile(fullbackup_file, fullbackup_copy)
					#update the full backup. It'll match the current contents of backup target
					subprocess.check_call(cmd7z_fullbackup, stdout=subprocess.DEVNULL)
				except subprocess.CalledProcessError:
					print ("Exception! failed to run the 7z command : ")
					sys.exit()

				#remove the failsafe copy
				os.remove(fullbackup_copy)

				#finally update the manifest (its inspired by the fs journal)
				with open (manifest_file, "w") as fh_dump:
					json.dump(manifest_data, fh_dump)
				print ("Info : Manifest written to file")
					
				print ("Info : Backup completed")

			else:
				print ("Error: Please do a full backup prior to performing an incremental one")
				sys.exit()

	else:
		print ("Error: Please specify the backup operation (create : -bc) or (restore : -br) or (view : -bv)")
		display_error()



parser = argparse.ArgumentParser(description="\n Enky backup and hashing tool v1.0. Use this to create full / incremental / differential backups with encryption and compression. This tool can also create and check file hashes (sha256) as an alternative to the ZFS scrub function. Depends on Python 3.0 and 7zip. (2021/12/03)\n")
parser.add_argument("mode", help="<backup | checksum > specify the run mode")
parser.add_argument("-ht", "--hashtarget", help="specify the root path of the files that need to be hashed. Optional during hash check mode")
parser.add_argument("-hf", "--hashfile", help="file to store the hash. Mandatory for checksum mode")
parser.add_argument("-hc", "--hashcheck", action='store_true', help="run in hash check mode. Only needs the hash file")
parser.add_argument("-hs", "--hashstore", action='store_true', help="run in hash store mode. Computes hashes and stores in hashing file (-hf)")

parser.add_argument("-bl", "--backuplocation", help="Path to store the backups under. Will create if not present")
parser.add_argument("-bt", "--backuptarget", help="Directory to backup.")
parser.add_argument("-bn", "--backupname", default="n/a", help="Put a short comment to describe the backup (optional)")
parser.add_argument("-bc", "--backupcreate", action='store_true', help="create a backup from backuptarget")
parser.add_argument("-br", "--backuprestore", action='store_true', help="restore a backup into backuptarget")
parser.add_argument("-bf", "--backupfull", action='store_true', help="create a full backup")
parser.add_argument("-bi", "--backupincremental", action='store_true', help="create an incremental backup. Needs a full backup as the base")
parser.add_argument("-bd", "--backupdifferential", action='store_true', help="create a differential backup. Needs a full backup as the base")
parser.add_argument("-bv", "--backupview", action='store_true', help="lists the available backups at backuplocation (-bl)")
parser.add_argument("-bpv", "--backupprettyview", action='store_true', help="Displays a prettier table. Use with (-bv)")
parser.add_argument("-brn", "--backuprestorenumber", type=int, help="Use with backup restore (-br) to select from the list in view (-bv)")
parser.add_argument("-bci", "--backupcheckintegrity", action='store_true', help="Do a basic check to verify backup archive integrity. Specify the backup location (-bl)")


args = parser.parse_args()
print ("")
print (args.hashcheck)

if (args.mode == "backup"):
	print ("=>Enky running in backup mode")
	process_backup_mode(args)
elif (args.mode == "checksum"):
	print ("=>Enky running in checksum mode")
	process_checksum_mode(args)
else:
	display_error()

