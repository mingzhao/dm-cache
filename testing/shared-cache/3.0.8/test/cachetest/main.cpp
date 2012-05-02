#include "cachetest.h"
#include <unistd.h>
#include <fcntl.h>
#include <grace/system.h>
#include <grace/filesystem.h>

$appobject(CachetestApp);

// ==========================================================================
// METHOD CachetestApp::main
// ==========================================================================
int CachetestApp::main (void)
{
	string odevname = argv["--original-device"];
	string cdevname = argv["--cached-device"];
	int numsect = argv["--sectors"];
	int generation = 1;
	int blocksdone = 0;
	
	if (! cdevname)
	{
		ferr.writeln ("Missing cache device argument");
		return 1;
	}
	
	BlockDevice cdev (cdevname);

	char smap[numsect];
	for (int i=0; i<numsect; ++i) smap[i] = 0;
	
	srand (core.time.now());
	
	for (generation=1; generation<65; ++generation)
	{
		fout.writeln ("Generation %i" %format (generation));
		while (blocksdone < numsect)
		{
			sector_t sec = (sector_t) (rand() % numsect);
			while (smap[sec] == generation) sec = (sec+1) % numsect;
			string blk = "%J" %format ($("sec",(unsigned int)sec)->$("gen",generation));
			blk.pad (4096, ' ');
			cdev.writeBlock (blk, sec);
			smap[sec] = generation;
			blocksdone++;
		}
		fout.writeln (">> Blocks written");
		blocksdone = 0;
		for (int i=0; i<numsect; ++i) smap[i] = 0;
		
		fout.writeln (">> Syncing and flushing caches");
		sync();
		fs.save ("/proc/sys/vm/drop_caches", "3");
		
		cdev.reopenForReading();
		fout.writeln (">> Starting read-round");
		
		while (blocksdone < numsect)
		{
			sector_t sec = (sector_t) (rand() % numsect);
			while (smap[sec] == generation) sec = (sec+1) % numsect;
			string blk = cdev.readBlock (sec);
			value v;
			v.fromjson (blk);
			if (v["sec"].uval() != (unsigned int) sec)
			{
				ferr.writeln ("!!! sector validation error on sector %u"
							  " data=%J"
							  %format ((unsigned int) sec, v));
				ferr.writeln ("    rawblock[16] = <%s>" %format (blk.left(16)));
				blk = cdev.readBlock (sec);
				v.fromjson (blk);
				ferr.writeln ("    second lookup: %J" %format (v));
				return 1;
			}
			if (v["gen"].ival() != generation)
			{
				ferr.writeln ("!!! sector validation error on sector %u"
							  " data=%J"
							  %format ((unsigned int) sec, v));
				
				blk = cdev.readBlock (sec);
				v.fromjson (blk);
				ferr.writeln ("    second lookup: %J" %format (v));
				return 1;
			}
			ferr.puts (">>> sector %u ok    \r" %format ((unsigned int) sec));
			smap[sec] = generation;
			blocksdone++;
		}
		fout.writeln (">> Blocks read");
		blocksdone = 0;
		
		cdev.reopenForWriting();
	}
	
	return 0;
}

// ==========================================================================
// CONSTRUCTOR BlockDevice
// ==========================================================================
BlockDevice::BlockDevice (const string &device)
{
	devname = device;
	if (! fs.exists (device)) throw (couldNotAttachDeviceException());
	fd = open (device.str(), O_RDWR);
	if (fd < 0) throw (couldNotAttachDeviceException());
}

// ==========================================================================
// DESTRUCTOR BlockDevice
// ==========================================================================
BlockDevice::~BlockDevice (void)
{
	close (fd);
}

// ==========================================================================
// METHOD BlockDevice::reopenForReading
// ==========================================================================
void BlockDevice::reopenForReading (void)
{
	close (fd);
	fd = open (devname.str(), O_RDONLY);
}

// ==========================================================================
// METHOD BlockDevice::reopenForWriting
// ==========================================================================
void BlockDevice::reopenForWriting (void)
{
	close (fd);
	fd = open (devname.str(), O_RDWR);
}

// ==========================================================================
// METHOD BlockDevice::readBlock
// ==========================================================================
string *BlockDevice::readBlock (sector_t atSector)
{
	returnclass (string) res retain;
	char buf[4097];
	
	if (lseek (fd, atSector * 4096, SEEK_SET) == (off_t) (atSector*4096))
	{
		if (read (fd, buf, 4096) == 4096)
		{
			res.strcpy (buf, 4096);
		}
		else
		{
			ferr.writeln ("[%s] Could not read 4096 bytes at sector %u"
					 	  %format (devname, (unsigned int) atSector));
		}
	}
	else
	{
		ferr.writeln ("[%s] Error seeking to sector %u"
					  %format (devname, (unsigned int) atSector));
	}
	
	return &res;
}

// ==========================================================================
// METHOD BlockDevice::writeBlock
// ==========================================================================
bool BlockDevice::writeBlock (const string &what, sector_t atSector)
{
	if (what.strlen() != 4096) return false;
	if (lseek (fd, atSector * 4096, SEEK_SET) == (off_t) (atSector*4096))
	{
		size_t sz = write (fd, what.str(), 4096);
		if (sz == 4096) return true;
		ferr.writeln ("[%s] Error writing 4096 bytes at sector %u"
					  " write() returned %u" %format (devname,
					   (unsigned int) atSector, (unsigned int) sz));
		return false;
	}
	
	ferr.writeln ("[%s] Error seeking to sector %u"
			 	  %format (devname, (unsigned int) atSector));
	return false;
}
