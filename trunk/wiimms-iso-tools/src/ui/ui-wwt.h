
/***************************************************************************
 *                    __            __ _ ___________                       *
 *                    \ \          / /| |____   ____|                      *
 *                     \ \        / / | |    | |                           *
 *                      \ \  /\  / /  | |    | |                           *
 *                       \ \/  \/ /   | |    | |                           *
 *                        \  /\  /    | |    | |                           *
 *                         \/  \/     |_|    |_|                           *
 *                                                                         *
 *                           Wiimms ISO Tools                              *
 *                         http://wit.wiimm.de/                            *
 *                                                                         *
 ***************************************************************************
 *                                                                         *
 *   This file is part of the WIT project.                                 *
 *   Visit http://wit.wiimm.de/ for project details and sources.           *
 *                                                                         *
 *   Copyright (c) 2009-2015 by Dirk Clemens <wiimm@wiimm.de>              *
 *                                                                         *
 ***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   See file gpl-2.0.txt or http://www.gnu.org/licenses/gpl-2.0.txt       *
 *                                                                         *
 ***************************************************************************
 *                                                                         *
 *   >>>  This file is automatically generated by './src/gen-ui.c'.  <<<   *
 *   >>>                   Do not edit this file!                    <<<   *
 *                                                                         *
 ***************************************************************************/


#ifndef WIT_UI_WWT_H
#define WIT_UI_WWT_H
#include "lib-std.h"
#include "ui.h"

//
///////////////////////////////////////////////////////////////////////////////
///////////////                enum enumOptions                 ///////////////
///////////////////////////////////////////////////////////////////////////////

typedef enum enumOptions
{
	OPT_NONE,

	//----- command specific options -----

	OPT_AUTO,
	OPT_ALL,
	OPT_PART,
	OPT_SOURCE,
	OPT_NO_EXPAND,
	OPT_RECURSE,
	OPT_RDEPTH,
	OPT_PSEL,
	OPT_RAW,
	OPT_WBFS_ALLOC,
	OPT_EXCLUDE,
	OPT_EXCLUDE_PATH,
	OPT_INCLUDE,
	OPT_INCLUDE_PATH,
	OPT_INCLUDE_FIRST,
	OPT_ONE_JOB,
	OPT_JOB_LIMIT,
	OPT_IGNORE,
	OPT_IGNORE_FST,
	OPT_IGNORE_SETUP,
	OPT_LINKS,
	OPT_PMODE,
	OPT_FLAT,
	OPT_COPY_GC,
	OPT_NO_LINK,
	OPT_NEEK,
	OPT_ENC,
	OPT_MODIFY,
	OPT_NAME,
	OPT_ID,
	OPT_DISC_ID,
	OPT_BOOT_ID,
	OPT_TICKET_ID,
	OPT_TMD_ID,
	OPT_TT_ID,
	OPT_WBFS_ID,
	OPT_REGION,
	OPT_COMMON_KEY,
	OPT_IOS,
	OPT_HTTP,
	OPT_DOMAIN,
	OPT_WIIMMFI,
	OPT_TWIIMMFI,
	OPT_RM_FILES,
	OPT_ZERO_FILES,
	OPT_REPL_FILE,
	OPT_ADD_FILE,
	OPT_IGNORE_FILES,
	OPT_TRIM,
	OPT_ALIGN,
	OPT_ALIGN_PART,
	OPT_ALIGN_FILES,
	OPT_DEST,
	OPT_DEST2,
	OPT_AUTO_SPLIT,
	OPT_NO_SPLIT,
	OPT_SPLIT,
	OPT_SPLIT_SIZE,
	OPT_DISC_SIZE,
	OPT_PREALLOC,
	OPT_TRUNC,
	OPT_CHUNK_MODE,
	OPT_CHUNK_SIZE,
	OPT_MAX_CHUNKS,
	OPT_COMPRESSION,
	OPT_MEM,
	OPT_SIZE,
	OPT_HSS,
	OPT_WSS,
	OPT_RECOVER,
	OPT_NO_CHECK,
	OPT_REPAIR,
	OPT_NO_FREE,
	OPT_UPDATE,
	OPT_SYNC,
	OPT_SYNC_ALL,
	OPT_NEWER,
	OPT_OVERWRITE,
	OPT_REMOVE,
	OPT_WDF,
	OPT_WDF1,
	OPT_WDF2,
	OPT_WIA,
	OPT_GCZ,
	OPT_GCZ_ZIP,
	OPT_ISO,
	OPT_CISO,
	OPT_WBFS,
	OPT_FST,
	OPT_FILES,
	OPT_ITIME,
	OPT_MTIME,
	OPT_CTIME,
	OPT_ATIME,
	OPT_TIME,
	OPT_SET_TIME,
	OPT_LONG,
	OPT_SHOW,
	OPT_FRAGMENTS,
	OPT_NUMERIC,
	OPT_TECHNICAL,
	OPT_INODE,
	OPT_MIXED,
	OPT_UNIQUE,
	OPT_NO_HEADER,
	OPT_OLD_STYLE,
	OPT_SECTIONS,
	OPT_SORT,
	OPT_LIMIT,

	OPT__N_SPECIFIC, // == 110 

	//----- global options -----

	OPT_VERSION,
	OPT_HELP,
	OPT_XHELP,
	OPT_WIDTH,
	OPT_QUIET,
	OPT_VERBOSE,
	OPT_PROGRESS,
	OPT_SCAN_PROGRESS,
	OPT_LOGGING,
	OPT_ESC,
	OPT_IO,
	OPT_DIRECT,
	OPT_TITLES,
	OPT_UTF_8,
	OPT_NO_UTF_8,
	OPT_LANG,
	OPT_TEST,
	OPT_OLD,
	OPT_NEW,
	OPT_HOOK,
	OPT_FORCE,
	OPT_ALIGN_WDF,
	OPT_GCZ_BLOCK,

	OPT__N_TOTAL // == 133

} enumOptions;

//
///////////////////////////////////////////////////////////////////////////////
///////////////               enum enumOptionsBit               ///////////////
///////////////////////////////////////////////////////////////////////////////

//	*****  only for verification  *****

//typedef enum enumOptionsBit
//{
//	//----- command specific options -----
//
//	OB_AUTO			= 1llu << OPT_AUTO,
//	OB_ALL			= 1llu << OPT_ALL,
//	OB_PART			= 1llu << OPT_PART,
//	OB_SOURCE		= 1llu << OPT_SOURCE,
//	OB_NO_EXPAND		= 1llu << OPT_NO_EXPAND,
//	OB_RECURSE		= 1llu << OPT_RECURSE,
//	OB_RDEPTH		= 1llu << OPT_RDEPTH,
//	OB_PSEL			= 1llu << OPT_PSEL,
//	OB_RAW			= 1llu << OPT_RAW,
//	OB_WBFS_ALLOC		= 1llu << OPT_WBFS_ALLOC,
//	OB_EXCLUDE		= 1llu << OPT_EXCLUDE,
//	OB_EXCLUDE_PATH		= 1llu << OPT_EXCLUDE_PATH,
//	OB_INCLUDE		= 1llu << OPT_INCLUDE,
//	OB_INCLUDE_PATH		= 1llu << OPT_INCLUDE_PATH,
//	OB_INCLUDE_FIRST	= 1llu << OPT_INCLUDE_FIRST,
//	OB_ONE_JOB		= 1llu << OPT_ONE_JOB,
//	OB_JOB_LIMIT		= 1llu << OPT_JOB_LIMIT,
//	OB_IGNORE		= 1llu << OPT_IGNORE,
//	OB_IGNORE_FST		= 1llu << OPT_IGNORE_FST,
//	OB_IGNORE_SETUP		= 1llu << OPT_IGNORE_SETUP,
//	OB_LINKS		= 1llu << OPT_LINKS,
//	OB_PMODE		= 1llu << OPT_PMODE,
//	OB_FLAT			= 1llu << OPT_FLAT,
//	OB_COPY_GC		= 1llu << OPT_COPY_GC,
//	OB_NO_LINK		= 1llu << OPT_NO_LINK,
//	OB_NEEK			= 1llu << OPT_NEEK,
//	OB_ENC			= 1llu << OPT_ENC,
//	OB_MODIFY		= 1llu << OPT_MODIFY,
//	OB_NAME			= 1llu << OPT_NAME,
//	OB_ID			= 1llu << OPT_ID,
//	OB_DISC_ID		= 1llu << OPT_DISC_ID,
//	OB_BOOT_ID		= 1llu << OPT_BOOT_ID,
//	OB_TICKET_ID		= 1llu << OPT_TICKET_ID,
//	OB_TMD_ID		= 1llu << OPT_TMD_ID,
//	OB_TT_ID		= 1llu << OPT_TT_ID,
//	OB_WBFS_ID		= 1llu << OPT_WBFS_ID,
//	OB_REGION		= 1llu << OPT_REGION,
//	OB_COMMON_KEY		= 1llu << OPT_COMMON_KEY,
//	OB_IOS			= 1llu << OPT_IOS,
//	OB_HTTP			= 1llu << OPT_HTTP,
//	OB_DOMAIN		= 1llu << OPT_DOMAIN,
//	OB_WIIMMFI		= 1llu << OPT_WIIMMFI,
//	OB_TWIIMMFI		= 1llu << OPT_TWIIMMFI,
//	OB_RM_FILES		= 1llu << OPT_RM_FILES,
//	OB_ZERO_FILES		= 1llu << OPT_ZERO_FILES,
//	OB_REPL_FILE		= 1llu << OPT_REPL_FILE,
//	OB_ADD_FILE		= 1llu << OPT_ADD_FILE,
//	OB_IGNORE_FILES		= 1llu << OPT_IGNORE_FILES,
//	OB_TRIM			= 1llu << OPT_TRIM,
//	OB_ALIGN		= 1llu << OPT_ALIGN,
//	OB_ALIGN_PART		= 1llu << OPT_ALIGN_PART,
//	OB_ALIGN_FILES		= 1llu << OPT_ALIGN_FILES,
//	OB_DEST			= 1llu << OPT_DEST,
//	OB_DEST2		= 1llu << OPT_DEST2,
//	OB_AUTO_SPLIT		= 1llu << OPT_AUTO_SPLIT,
//	OB_NO_SPLIT		= 1llu << OPT_NO_SPLIT,
//	OB_SPLIT		= 1llu << OPT_SPLIT,
//	OB_SPLIT_SIZE		= 1llu << OPT_SPLIT_SIZE,
//	OB_DISC_SIZE		= 1llu << OPT_DISC_SIZE,
//	OB_PREALLOC		= 1llu << OPT_PREALLOC,
//	OB_TRUNC		= 1llu << OPT_TRUNC,
//	OB_CHUNK_MODE		= 1llu << OPT_CHUNK_MODE,
//	OB_CHUNK_SIZE		= 1llu << OPT_CHUNK_SIZE,
//	OB_MAX_CHUNKS		= 1llu << OPT_MAX_CHUNKS,
//	OB_COMPRESSION		= 1llu << OPT_COMPRESSION,
//	OB_MEM			= 1llu << OPT_MEM,
//	OB_SIZE			= 1llu << OPT_SIZE,
//	OB_HSS			= 1llu << OPT_HSS,
//	OB_WSS			= 1llu << OPT_WSS,
//	OB_RECOVER		= 1llu << OPT_RECOVER,
//	OB_NO_CHECK		= 1llu << OPT_NO_CHECK,
//	OB_REPAIR		= 1llu << OPT_REPAIR,
//	OB_NO_FREE		= 1llu << OPT_NO_FREE,
//	OB_UPDATE		= 1llu << OPT_UPDATE,
//	OB_SYNC			= 1llu << OPT_SYNC,
//	OB_SYNC_ALL		= 1llu << OPT_SYNC_ALL,
//	OB_NEWER		= 1llu << OPT_NEWER,
//	OB_OVERWRITE		= 1llu << OPT_OVERWRITE,
//	OB_REMOVE		= 1llu << OPT_REMOVE,
//	OB_WDF			= 1llu << OPT_WDF,
//	OB_WDF1			= 1llu << OPT_WDF1,
//	OB_WDF2			= 1llu << OPT_WDF2,
//	OB_WIA			= 1llu << OPT_WIA,
//	OB_GCZ			= 1llu << OPT_GCZ,
//	OB_GCZ_ZIP		= 1llu << OPT_GCZ_ZIP,
//	OB_ISO			= 1llu << OPT_ISO,
//	OB_CISO			= 1llu << OPT_CISO,
//	OB_WBFS			= 1llu << OPT_WBFS,
//	OB_FST			= 1llu << OPT_FST,
//	OB_FILES		= 1llu << OPT_FILES,
//	OB_ITIME		= 1llu << OPT_ITIME,
//	OB_MTIME		= 1llu << OPT_MTIME,
//	OB_CTIME		= 1llu << OPT_CTIME,
//	OB_ATIME		= 1llu << OPT_ATIME,
//	OB_TIME			= 1llu << OPT_TIME,
//	OB_SET_TIME		= 1llu << OPT_SET_TIME,
//	OB_LONG			= 1llu << OPT_LONG,
//	OB_SHOW			= 1llu << OPT_SHOW,
//	OB_FRAGMENTS		= 1llu << OPT_FRAGMENTS,
//	OB_NUMERIC		= 1llu << OPT_NUMERIC,
//	OB_TECHNICAL		= 1llu << OPT_TECHNICAL,
//	OB_INODE		= 1llu << OPT_INODE,
//	OB_MIXED		= 1llu << OPT_MIXED,
//	OB_UNIQUE		= 1llu << OPT_UNIQUE,
//	OB_NO_HEADER		= 1llu << OPT_NO_HEADER,
//	OB_OLD_STYLE		= 1llu << OPT_OLD_STYLE,
//	OB_SECTIONS		= 1llu << OPT_SECTIONS,
//	OB_SORT			= 1llu << OPT_SORT,
//	OB_LIMIT		= 1llu << OPT_LIMIT,
//
//	//----- group & command options -----
//
//	OB_GRP_TITLES		= 0,
//
//	OB_GRP_READ_WBFS	= OB_AUTO
//				| OB_ALL
//				| OB_PART,
//
//	OB_GRP_MOD_WBFS		= OB_AUTO
//				| OB_ALL
//				| OB_PART
//				| OB_NO_CHECK,
//
//	OB_GRP_FST_OPTIONS	= OB_IGNORE_FST
//				| OB_IGNORE_SETUP
//				| OB_LINKS,
//
//	OB_GRP_EXCLUDE		= OB_EXCLUDE
//				| OB_EXCLUDE_PATH
//				| OB_INCLUDE
//				| OB_INCLUDE_PATH
//				| OB_INCLUDE_FIRST
//				| OB_ONE_JOB
//				| OB_JOB_LIMIT,
//
//	OB_GRP_IGN_EXCLUDE	= OB_EXCLUDE
//				| OB_EXCLUDE_PATH
//				| OB_INCLUDE
//				| OB_INCLUDE_PATH
//				| OB_INCLUDE_FIRST
//				| OB_ONE_JOB
//				| OB_JOB_LIMIT
//				| OB_IGNORE
//				| OB_GRP_FST_OPTIONS,
//
//	OB_GRP_VERBOSE		= 0,
//
//	OB_GRP_XTIME		= OB_ITIME
//				| OB_MTIME
//				| OB_CTIME
//				| OB_ATIME,
//
//	OB_GRP_TIME		= OB_GRP_XTIME
//				| OB_TIME,
//
//	OB_GRP_OUTMODE_EDIT	= OB_WDF
//				| OB_WDF1
//				| OB_WDF2
//				| OB_ISO
//				| OB_CISO
//				| OB_WBFS,
//
//	OB_GRP_OUTMODE		= OB_GRP_OUTMODE_EDIT
//				| OB_WIA
//				| OB_GCZ
//				| OB_GCZ_ZIP
//				| OB_FST,
//
//	OB_GRP_PARTITIONS	= OB_PSEL
//				| OB_RAW,
//
//	OB_GRP_FST_SELECT	= OB_PMODE
//				| OB_FLAT
//				| OB_FILES
//				| OB_COPY_GC
//				| OB_NO_LINK
//				| OB_NEEK,
//
//	OB_GRP_PATCH		= OB_ENC
//				| OB_MODIFY
//				| OB_NAME
//				| OB_ID
//				| OB_DISC_ID
//				| OB_BOOT_ID
//				| OB_TICKET_ID
//				| OB_TMD_ID
//				| OB_TT_ID
//				| OB_WBFS_ID
//				| OB_REGION
//				| OB_COMMON_KEY
//				| OB_IOS
//				| OB_HTTP
//				| OB_DOMAIN
//				| OB_WIIMMFI
//				| OB_TWIIMMFI
//				| OB_RM_FILES
//				| OB_ZERO_FILES,
//
//	OB_GRP_RELOCATE		= OB_REPL_FILE
//				| OB_ADD_FILE
//				| OB_IGNORE_FILES
//				| OB_TRIM
//				| OB_ALIGN
//				| OB_ALIGN_PART
//				| OB_ALIGN_FILES,
//
//	OB_GRP_SPLIT_CHUNK	= OB_AUTO_SPLIT
//				| OB_NO_SPLIT
//				| OB_SPLIT
//				| OB_SPLIT_SIZE
//				| OB_DISC_SIZE
//				| OB_PREALLOC
//				| OB_TRUNC
//				| OB_CHUNK_MODE
//				| OB_CHUNK_SIZE
//				| OB_MAX_CHUNKS
//				| OB_COMPRESSION
//				| OB_MEM,
//
//	OB_CMD_VERSION		= OB_SECTIONS
//				| OB_LONG,
//
//	OB_CMD_HELP		= ~(u64)0,
//
//	OB_CMD_INFO		= OB_SECTIONS
//				| OB_LONG,
//
//	OB_CMD_TEST		= ~(u64)0,
//
//	OB_CMD_ERROR		= OB_SECTIONS
//				| OB_NO_HEADER
//				| OB_LONG,
//
//	OB_CMD_COMPR		= OB_SECTIONS
//				| OB_NO_HEADER
//				| OB_LONG
//				| OB_NUMERIC,
//
//	OB_CMD_FEATURES		= 0,
//
//	OB_CMD_EXCLUDE		= OB_EXCLUDE
//				| OB_EXCLUDE_PATH,
//
//	OB_CMD_TITLES		= OB_GRP_TITLES,
//
//	OB_CMD_GETTITLES	= 0,
//
//	OB_CMD_FIND		= OB_GRP_READ_WBFS
//				| OB_NO_HEADER
//				| OB_LONG
//				| OB_OLD_STYLE
//				| OB_SECTIONS,
//
//	OB_CMD_SPACE		= OB_GRP_READ_WBFS
//				| OB_NO_HEADER
//				| OB_LONG,
//
//	OB_CMD_ANALYZE		= OB_GRP_READ_WBFS
//				| OB_LONG,
//
//	OB_CMD_DUMP		= OB_GRP_TITLES
//				| OB_GRP_READ_WBFS
//				| OB_INODE
//				| OB_LONG
//				| OB_SHOW,
//
//	OB_CMD_ID6		= OB_GRP_READ_WBFS
//				| OB_GRP_EXCLUDE,
//
//	OB_CMD_LIST		= OB_GRP_TITLES
//				| OB_GRP_READ_WBFS
//				| OB_GRP_EXCLUDE
//				| OB_MIXED
//				| OB_UNIQUE
//				| OB_SORT
//				| OB_GRP_TIME
//				| OB_LONG
//				| OB_FRAGMENTS
//				| OB_NO_HEADER
//				| OB_SECTIONS,
//
//	OB_CMD_LIST_L		= OB_CMD_LIST,
//
//	OB_CMD_LIST_LL		= OB_CMD_LIST,
//
//	OB_CMD_LIST_LLL		= OB_CMD_LIST,
//
//	OB_CMD_LIST_A		= OB_CMD_LIST,
//
//	OB_CMD_LIST_M		= OB_CMD_LIST,
//
//	OB_CMD_LIST_U		= OB_CMD_LIST,
//
//	OB_CMD_LIST_F		= OB_CMD_LIST,
//
//	OB_CMD_FORMAT		= OB_GRP_TITLES
//				| OB_SIZE
//				| OB_SPLIT
//				| OB_SPLIT_SIZE
//				| OB_HSS
//				| OB_WSS
//				| OB_RECOVER
//				| OB_INODE,
//
//	OB_CMD_RECOVER		= OB_GRP_TITLES
//				| OB_GRP_READ_WBFS,
//
//	OB_GRP_CHECK		= OB_GRP_TITLES
//				| OB_GRP_READ_WBFS
//				| OB_SECTIONS
//				| OB_LONG,
//
//	OB_CMD_CHECK		= OB_GRP_CHECK
//				| OB_REPAIR,
//
//	OB_CMD_REPAIR		= OB_GRP_CHECK
//				| OB_REPAIR,
//
//	OB_CMD_EDIT		= OB_AUTO
//				| OB_PART,
//
//	OB_CMD_PHANTOM		= OB_GRP_MOD_WBFS
//				| OB_WBFS_ALLOC,
//
//	OB_CMD_TRUNCATE		= OB_GRP_MOD_WBFS,
//
//	OB_CMD_SYNC		= OB_GRP_TITLES
//				| OB_GRP_MOD_WBFS
//				| OB_WBFS_ALLOC
//				| OB_SOURCE
//				| OB_NO_EXPAND
//				| OB_RECURSE
//				| OB_RDEPTH
//				| OB_GRP_IGN_EXCLUDE
//				| OB_GRP_VERBOSE
//				| OB_SECTIONS
//				| OB_GRP_PATCH
//				| OB_GRP_RELOCATE
//				| OB_GRP_PARTITIONS
//				| OB_REMOVE
//				| OB_TRUNC
//				| OB_NEWER
//				| OB_SYNC_ALL,
//
//	OB_CMD_UPDATE		= OB_CMD_SYNC
//				| OB_SYNC,
//
//	OB_CMD_NEW		= OB_CMD_UPDATE,
//
//	OB_CMD_ADD		= OB_CMD_UPDATE
//				| OB_UPDATE
//				| OB_OVERWRITE,
//
//	OB_CMD_DUP		= OB_GRP_TITLES
//				| OB_GRP_READ_WBFS
//				| OB_NO_CHECK
//				| OB_DEST
//				| OB_DEST2
//				| OB_OVERWRITE,
//
//	OB_CMD_EXTRACT		= OB_GRP_TITLES
//				| OB_GRP_MOD_WBFS
//				| OB_GRP_EXCLUDE
//				| OB_GRP_VERBOSE
//				| OB_LONG
//				| OB_SECTIONS
//				| OB_DEST
//				| OB_DEST2
//				| OB_GRP_SPLIT_CHUNK
//				| OB_GRP_PATCH
//				| OB_GRP_PARTITIONS
//				| OB_GRP_OUTMODE
//				| OB_GRP_FST_SELECT
//				| OB_LINKS
//				| OB_UNIQUE
//				| OB_IGNORE
//				| OB_REMOVE
//				| OB_UPDATE
//				| OB_OVERWRITE
//				| OB_TRUNC,
//
//	OB_CMD_SCRUB		= OB_GRP_TITLES
//				| OB_GRP_MOD_WBFS
//				| OB_GRP_EXCLUDE
//				| OB_GRP_VERBOSE
//				| OB_LONG
//				| OB_SECTIONS
//				| OB_GRP_PATCH
//				| OB_GRP_PARTITIONS,
//
//	OB_CMD_REMOVE		= OB_GRP_TITLES
//				| OB_GRP_MOD_WBFS
//				| OB_GRP_EXCLUDE
//				| OB_GRP_VERBOSE
//				| OB_SECTIONS
//				| OB_UNIQUE
//				| OB_IGNORE
//				| OB_NO_FREE,
//
//	OB_CMD_RENAME		= OB_GRP_TITLES
//				| OB_GRP_MOD_WBFS
//				| OB_GRP_EXCLUDE
//				| OB_IGNORE
//				| OB_ISO
//				| OB_WBFS,
//
//	OB_CMD_SETTITLE		= OB_CMD_RENAME,
//
//	OB_CMD_TOUCH		= OB_GRP_TITLES
//				| OB_GRP_MOD_WBFS
//				| OB_GRP_EXCLUDE
//				| OB_UNIQUE
//				| OB_IGNORE
//				| OB_ITIME
//				| OB_MTIME
//				| OB_CTIME
//				| OB_ATIME
//				| OB_SET_TIME,
//
//	OB_CMD_VERIFY		= OB_GRP_TITLES
//				| OB_GRP_MOD_WBFS
//				| OB_GRP_EXCLUDE
//				| OB_GRP_VERBOSE
//				| OB_LIMIT
//				| OB_GRP_PARTITIONS
//				| OB_IGNORE_FILES
//				| OB_UNIQUE
//				| OB_IGNORE
//				| OB_REMOVE
//				| OB_NO_FREE
//				| OB_LONG
//				| OB_TECHNICAL,
//
//	OB_CMD_SKELETON		= OB_GRP_TITLES
//				| OB_GRP_MOD_WBFS
//				| OB_GRP_EXCLUDE
//				| OB_GRP_PARTITIONS
//				| OB_IGNORE
//				| OB_GRP_OUTMODE_EDIT
//				| OB_DEST
//				| OB_DEST2,
//
//	OB_CMD_FILETYPE		= OB_IGNORE
//				| OB_GRP_FST_OPTIONS
//				| OB_NO_HEADER
//				| OB_LONG,
//
//} enumOptionsBit;

//
///////////////////////////////////////////////////////////////////////////////
///////////////                enum enumCommands                ///////////////
///////////////////////////////////////////////////////////////////////////////

typedef enum enumCommands
{
	CMD__NONE,

	CMD_VERSION,
	CMD_HELP,
	CMD_INFO,
	CMD_TEST,
	CMD_ERROR,
	CMD_COMPR,
	CMD_FEATURES,
	CMD_EXCLUDE,
	CMD_TITLES,
	CMD_GETTITLES,

	CMD_FIND,
	CMD_SPACE,
	CMD_ANALYZE,
	CMD_DUMP,

	CMD_ID6,
	CMD_LIST,
	CMD_LIST_L,
	CMD_LIST_LL,
	CMD_LIST_LLL,
	CMD_LIST_A,
	CMD_LIST_M,
	CMD_LIST_U,
	CMD_LIST_F,

	CMD_FORMAT,
	CMD_RECOVER,
	CMD_CHECK,
	CMD_REPAIR,
	CMD_EDIT,
	CMD_PHANTOM,
	CMD_TRUNCATE,

	CMD_ADD,
	CMD_UPDATE,
	CMD_NEW,
	CMD_SYNC,
	CMD_DUP,
	CMD_EXTRACT,
	CMD_SCRUB,
	CMD_REMOVE,
	CMD_RENAME,
	CMD_SETTITLE,
	CMD_TOUCH,
	CMD_VERIFY,
	CMD_SKELETON,

	CMD_FILETYPE,

	CMD__N // == 45

} enumCommands;

//
///////////////////////////////////////////////////////////////////////////////
///////////////                   enumGetOpt                    ///////////////
///////////////////////////////////////////////////////////////////////////////

typedef enum enumGetOpt
{
	GO_SHOW			= '+',

	GO_ONE_JOB		= '1',

	GO__ERR			= '?',

	GO_ALL			= 'A',
	GO_WBFS			= 'B',
	GO_CISO			= 'C',
	GO_DEST2		= 'D',
	GO_ESC			= 'E',
	GO_NO_HEADER		= 'H',
	GO_ISO			= 'I',
	GO_LOGGING		= 'L',
	GO_MIXED		= 'M',
	GO_INCLUDE_PATH		= 'N',
	GO_PROGRESS		= 'P',
	GO_REMOVE		= 'R',
	GO_SORT			= 'S',
	GO_TITLES		= 'T',
	GO_UNIQUE		= 'U',
	GO_VERSION		= 'V',
	GO_WDF			= 'W',
	GO_EXCLUDE_PATH		= 'X',
	GO_SPLIT_SIZE		= 'Z',

	GO_AUTO			= 'a',
	GO_DEST			= 'd',
	GO_NEWER		= 'e',
	GO_FORCE		= 'f',
	GO_HELP			= 'h',
	GO_IGNORE		= 'i',
	GO_LONG			= 'l',
	GO_INCLUDE		= 'n',
	GO_OVERWRITE		= 'o',
	GO_PART			= 'p',
	GO_QUIET		= 'q',
	GO_RECURSE		= 'r',
	GO_SIZE			= 's',
	GO_TEST			= 't',
	GO_UPDATE		= 'u',
	GO_VERBOSE		= 'v',
	GO_EXCLUDE		= 'x',
	GO_SYNC			= 'y',
	GO_SPLIT		= 'z',

	GO_XHELP		= 0x80,
	GO_WIDTH,
	GO_SCAN_PROGRESS,
	GO_IO,
	GO_DIRECT,
	GO_UTF_8,
	GO_NO_UTF_8,
	GO_LANG,
	GO_OLD,
	GO_NEW,
	GO_SOURCE,
	GO_NO_EXPAND,
	GO_RDEPTH,
	GO_PSEL,
	GO_RAW,
	GO_WBFS_ALLOC,
	GO_INCLUDE_FIRST,
	GO_JOB_LIMIT,
	GO_IGNORE_FST,
	GO_IGNORE_SETUP,
	GO_LINKS,
	GO_PMODE,
	GO_FLAT,
	GO_COPY_GC,
	GO_NO_LINK,
	GO_NEEK,
	GO_HOOK,
	GO_ENC,
	GO_MODIFY,
	GO_NAME,
	GO_ID,
	GO_DISC_ID,
	GO_BOOT_ID,
	GO_TICKET_ID,
	GO_TMD_ID,
	GO_TT_ID,
	GO_WBFS_ID,
	GO_REGION,
	GO_COMMON_KEY,
	GO_IOS,
	GO_HTTP,
	GO_DOMAIN,
	GO_WIIMMFI,
	GO_TWIIMMFI,
	GO_RM_FILES,
	GO_ZERO_FILES,
	GO_REPL_FILE,
	GO_ADD_FILE,
	GO_IGNORE_FILES,
	GO_TRIM,
	GO_ALIGN,
	GO_ALIGN_PART,
	GO_ALIGN_FILES,
	GO_AUTO_SPLIT,
	GO_NO_SPLIT,
	GO_DISC_SIZE,
	GO_PREALLOC,
	GO_TRUNC,
	GO_CHUNK_MODE,
	GO_CHUNK_SIZE,
	GO_MAX_CHUNKS,
	GO_COMPRESSION,
	GO_MEM,
	GO_HSS,
	GO_WSS,
	GO_RECOVER,
	GO_NO_CHECK,
	GO_REPAIR,
	GO_NO_FREE,
	GO_SYNC_ALL,
	GO_WDF1,
	GO_WDF2,
	GO_ALIGN_WDF,
	GO_WIA,
	GO_GCZ,
	GO_GCZ_ZIP,
	GO_GCZ_BLOCK,
	GO_FST,
	GO_FILES,
	GO_ITIME,
	GO_MTIME,
	GO_CTIME,
	GO_ATIME,
	GO_TIME,
	GO_SET_TIME,
	GO_FRAGMENTS,
	GO_NUMERIC,
	GO_TECHNICAL,
	GO_INODE,
	GO_OLD_STYLE,
	GO_SECTIONS,
	GO_LIMIT,

} enumGetOpt;

//
///////////////////////////////////////////////////////////////////////////////
///////////////                  external vars                  ///////////////
///////////////////////////////////////////////////////////////////////////////

extern const InfoOption_t OptionInfo[OPT__N_TOTAL+1];
extern const CommandTab_t CommandTab[];
extern const char OptionShort[];
extern const struct option OptionLong[];
extern u8 OptionUsed[OPT__N_TOTAL+1];
extern const u8 OptionIndex[OPT_INDEX_SIZE];
extern const InfoCommand_t CommandInfo[CMD__N+1];
extern const InfoUI_t InfoUI;

//
///////////////////////////////////////////////////////////////////////////////
///////////////                       END                       ///////////////
///////////////////////////////////////////////////////////////////////////////

#endif // WIT_UI_WWT_H

