#ifndef _cachetest_H
#define _cachetest_H 1
#include <grace/application.h>

//  -------------------------------------------------------------------------
/// Main application class.
//  -------------------------------------------------------------------------
class CachetestApp : public application
{
public:
				 /// Constructor.
				 /// Sets argument parsing options.
		 		 CachetestApp (void) :
					application ("net.xl-is.tools.cachetest")
				 {
				 	opt = $("-h", $("long", "--help"))->
				 		  $("-o", $("long", "--original-device"))->
				 		  $("-c", $("long", "--cached-device"))->
				 		  $("-s", $("long", "--sectors"))->
				 		  $("--original-device", $("argc",1))->
				 		  $("--cached-device", $("argc",1))->
				 		  $("--sectors", $("argc",1)->$("default",16384));
				 }
				 
				 /// Destructor
				~CachetestApp (void)
				 {
				 }

				 /// Main loop	
	int			 main (void);
};

typedef unsigned long sector_t;

$exception (couldNotAttachDeviceException, "Could not attach to device");

//  -------------------------------------------------------------------------
/// Abstraction of a block device
//  -------------------------------------------------------------------------
class BlockDevice
{
public:
				 /// Constructor.
				 /// Attaches to the block device with raw i/o.
				 BlockDevice (const string &dev);
				 
				 /// Destructor.
				 /// Closes filedescriptors.
				~BlockDevice (void);
				
				/// Reads a single block from disk.
				/// \param atSector The disk sector to read.
				/// \returns A string with a 512 byte block.
	string		*readBlock (sector_t atSector);
	
				 /// Writes a block to disk.
				 /// \param with The 512 byte block to write. Other
				 ///             sizes are rejected.
				 /// \param atSector The sector to write to.
	bool		 writeBlock (const string &with, sector_t atSector);
	
				 /// Reopens device node for uncached reading.
	void		 reopenForReading (void);
	
				 /// Reopens device for writing.
	void		 reopenForWriting (void);

protected:
	int			 fd; ///< The filedescriptor to the device node.
	string		 devname; ///< The name/path of the device node.
};

#endif
