#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sqlite3.h"

static int callback(void *NotUsed, int argc, char **argv, char **azColName){
   int i;

   for(i=0; i<argc; i++){
     printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
   }
   printf("\n");
   return 0;
}


/* cmd @datasize @nrows @insert @dbname */
int main(int argc, char **argv){
	sqlite3 *db;
	char *zErrMsg = 0;
	int rc;
	long i;
	long datasize, nrows;
	char *dbname;
	char *data, *cmd;
	int whether_insert;
	int sync_mode = 2;

	if ( argc != 5 &&  argc != 6) {
		fprintf(stderr, "Usage: %s @datasize @nrows @insert @dbname (@syncmode)\n", argv[0]);
		return(1);
	}

	datasize = atol(argv[1]);
	nrows = atol(argv[2]);
	whether_insert = atoi(argv[3]);
	dbname = argv[4];

	if (argc==6)
		sync_mode = atoi(argv[5]);

	//prepare data
	cmd = malloc(datasize + 70);
	if (!cmd)
		goto errout1;
	data = malloc(datasize + 1);
	if (!cmd || !data)
		goto errout2;
	memset(data, 'x', datasize);
	data[datasize] = '\0';

	//Open Database
	rc = sqlite3_open(dbname, &db);
	if( rc ){
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
		goto errout3;
	}

	sprintf(cmd, "PRAGMA synchronous=%d;", sync_mode);
	sqlite3_exec(db, cmd, callback, 0, &zErrMsg);

	if (!whether_insert)
		goto finish_out;

	for (i = 0; i < nrows; i++) {
		snprintf(cmd, datasize + 70, "INSERT INTO tbl VALUES (%ld,\"%s\");", i, data);
		//printf("data=%s\ncmd=%s\n", data, cmd);
		rc = sqlite3_exec(db, cmd, callback, 0, &zErrMsg);
		if ( rc != SQLITE_OK ) {
			fprintf(stderr, "SQL error: %s\n", zErrMsg);
			sqlite3_free(zErrMsg);
		}
	}

finish_out:
	sqlite3_close(db);
	return 0;

errout3:
	sqlite3_close(db);
errout2:
	printf("errout2\n");
	free(cmd);
errout1:
	printf("errout1\n");
	return 0;
}

