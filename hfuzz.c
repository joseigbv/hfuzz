
/*************************
* fuzzer http simple
* compilacion:  gcc -Wall -O2 -DHTTP11 -lpthread hfuzz.c -o hfuzz 
* -DHTTP11 para utilizar HTTP/1.1 
* Nota: para HTTP usar "delegate"
*    delegated -P80 SERVER=http MOUNT="/ * https://www.wikipedia.org/ *" STLS=fsv:https
*************************/

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#include <ctype.h>


/*************************
 * parametrizacion
 *************************/

// configuracion
#define HOSTNAME "testphp.vulnweb.com"
#define PORT 80
#define MAX_THREADS 100
#define USER_AGENT "Mozilla/5.0 (Windows NT 6.0; rv:12.0)"
#define DELAY 10000	// 10 ms

// tamanio buffers
#define SZ_SBUF	16384
#define SZ_URL 512
#define SZ_LINE 64
#define SZ_URLENC 256
#define SZ_POST 1024
#define SZ_RESULT 128
#define SZ_HEADER 128
#define SZ_REFERER 256


/*************************
 * threads
 *************************/

#define ARGS(x)	(*(t_args *)args).x
#define LOCK(x) pthread_mutex_lock(&lck_##x)
#define UNLOCK(x) pthread_mutex_unlock(&lck_##x)

// bloqueos 
pthread_mutex_t lck_print;
pthread_mutex_t lck_read;

// argumentos thread
typedef struct { int thread_id; } t_args;

// otros parametros globales
struct sockaddr_in addr;  
struct hostent *host;


/*************************
 * funciones
 *************************/

// mensaje de erro y salimos
void abort_(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

// convierte integer a hex
inline char to_hex(char code) 
{
	static const char hex[] = "0123456789abcdef";
	return hex[code & 15];
}

// devuelve version urlenc de str
char *url_encode(const char *str, char *buf) 
{
	const char *pstr = str;
	char *pbuf = buf;

	while (*pstr) 
	{
		// caracteres que no se tocan
		if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' 
			|| *pstr == '~') *pbuf++ = *pstr;

			// espacio -> + 
			else if (*pstr == ' ') *pbuf++ = '+';

				// el resto
				else 
				{
					*pbuf++ = '%';
					*pbuf++ = to_hex(*pstr >> 4);
					*pbuf++ = to_hex(*pstr & 15);
				}

		pstr++;
	}

	*pbuf = '\0';

	return buf;
}

// lectura concurrente palabra (stdin)
int readln(char *line)
{
	char *r;

	LOCK(read);
	r = fgets(line, SZ_LINE, stdin);
	line[strlen(line) - 1] = '\0';
	UNLOCK(read);

	return r != NULL;
}

// devuelve milisegundos 
double crono()
{
	struct timeval tim;

	gettimeofday(&tim, NULL);

	return ((tim.tv_sec * 1000000) + 
		tim.tv_usec) / 1000;
}

// conexion 
int http_open()
{
	int sock; 


	// creamos socket
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) 
		abort_("error al abrir socket");

	// conectamos 
	if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) == -1) 
		abort_("error de conexion");

	return sock;
}

// desconexion http
void http_close(int sock)
{
	close(sock); 
}

// respuesta http
int http_recv(int sock, char *sbuf)
{
	int rv, sz = 0; 
	char *p = sbuf;

#ifdef HTTP11

	// leemos primer chunk
	if ((sz = recv(sock, sbuf, SZ_SBUF, 0)) == -1)
		abort_("error en recepcion");

	// mas "trozos" ?
	if (strstr(sbuf, "Transfer-Encoding: chunked"))
	{
		// mientras no marca de fin de chunks
		while (!strstr(p, "0\r\n\r\n") && sz < SZ_SBUF)
		{
			p = sbuf + sz; 

			// leemos siguiente chunk
			if ((rv = recv(sock, p, SZ_SBUF - sz, 0)) == -1)
				abort_("error en recepcion");

			sz += rv;
		}
	}

#else 

	do
	{
		// leemos hasta devuelto 0 bytes
		if ((rv = recv(sock, p, SZ_SBUF - sz, 0)) == -1)
			abort_("error en recepcion");

		sz += rv;
		p += rv; 

	} while (rv && sz < SZ_SBUF);

#endif

	// terminamos
	sz = sz < SZ_SBUF ? sz : SZ_SBUF; 
	sbuf[sz - 1] = '\0';

	return sz;
}

// peticion http
int http_send(int sock, const char *sbuf)
{
	int sz; 

	// send
	if ((sz = send(sock, sbuf, strlen(sbuf), 0)) == -1)
		abort_("error en envio");

	return sz;
}

// devuelve cabecera (Content-Length: 62)
int http_head(const char *header, const char *sbuf, char *val)
{
	char *idx;
	char h[SZ_HEADER];
	int r = 0;

	// ejemplo lectura cabecera http
	if ((idx = strstr(sbuf, header)))
	{
		strncpy(h, header, SZ_HEADER); 
		strncat(h, ": %[^\r\n]", SZ_HEADER);
		r = sscanf(idx, h, val);	
	}

	return r;
}

// peticiones http
void *run(void *args)
{
	int sock, sz, code;
	int id, thread_id;
	char *sbuf, *psn, *prv; 
	double start, stop;

	char result[SZ_RESULT];
	char line[SZ_LINE];
	char urlenc[SZ_URLENC];

	char url[SZ_URL];
	char post[SZ_POST];
	char referer[SZ_REFERER];
	char cookie[SZ_POST];
	char ctype[SZ_HEADER];


        // argumentos (in)
        id = thread_id = ARGS(thread_id);

	// reservamos memoria
	if ((sbuf = psn = (char *) malloc(SZ_SBUF))== NULL)
		abort_("error de asignacion de memoria");

	// conectamos
	sock = http_open();

	// fuzz de parametros
	while (readln(line)) 
	{
		// convertimos a urlenc
		url_encode(line, urlenc);

/*******************************************************************************************/
/* editar aqui para fuzzing !!! */

		// url, cookies, posts, ...
		sprintf(url, "/userinfo.php");
		sprintf(post, "uname=test&pass=%s", urlenc);
		sprintf(cookie, "login=test%%2F%s", urlenc);
		sprintf(referer, "http://testphp.vulnweb.com/login.php");

		// construimos peticion 
#ifdef HTTP11
		sprintf(psn, "POST %s HTTP/1.1\r\n", url);
#else
		sprintf(psn, "POST %s HTTP/1.0\r\n", url);
#endif

		sprintf(psn, "%sHost: %s\r\n", psn, HOSTNAME);
		sprintf(psn, "%sUser-Agent: %s\r\n", psn, USER_AGENT);
		sprintf(psn, "%sReferer: %s\r\n", psn, referer);
		sprintf(psn, "%sCookie: %s\r\n", psn, cookie);
   		sprintf(psn, "%sContent-Type: application/x-www-form-urlencoded\r\n", psn);
		sprintf(psn, "%sContent-Length: %d\r\n", psn, (int) strlen(post));
		sprintf(psn, "%s\r\n", psn);
		sprintf(psn, "%s%s\r\n", psn, post);

/* hasta aqui */
/*******************************************************************************************/

		// iniciamos cronometro
		start = crono();

		// enviamos peticion
		sz = http_send(sock, psn); 

		// apuntamos bufer a zona recepcion
		sbuf[sz] = '\n'; 
		prv = psn + sz + 1;

		do {
			// leemos respuesta
			sz = http_recv(sock, prv);

			// HTTP result string ?
			if (sscanf(prv, "%[^\r\n]", result) == -1) 
				abort_("error de lectura"); 

			// codigo devuelto ?
			if (sscanf(prv, "HTTP/1.1 %d ", &code) == -1)
				abort_("error de lectura"); 

			http_head("Content-Type", prv, ctype);

		} while (code == 100);
		
		// paramos cronometro
		stop = crono();

		// imprimimos resultados
		LOCK(print);

		fprintf(stderr, "--------------------------------------------\n\n");
		fprintf(stderr, ">>> id: %d <<<\n\n%s\n", id, sbuf);

		printf("%d\t%s\t%d\t%d bytes\t%.0f ms\tPOST\t%s\t%s\t%s\n", 
			id, line, code, sz, stop - start, url, result, ctype);

		UNLOCK(print);

		// siguiente
		id += MAX_THREADS;

		// se ha cerrado la conexion ? volvemos a abrir
#ifdef HTTP11
		if (strstr(prv, "Connection: close"))
#endif
		{
			// cerramos socket
			http_close(sock); 

			// reconectamos
			sock = http_open();
		}

		// esperamos
		usleep(DELAY);
	}

	// liberamos memoria
	free(sbuf);

	// desconectamos
	http_close(sock);

	return NULL;
}

// funcion principal
int main()
{
	int th;
	pthread_t threads[MAX_THREADS];
	t_args args[MAX_THREADS];

	// resolucion host
	host = gethostbyname(HOSTNAME);

	// rellenamos estructura server_addr
	addr.sin_family = AF_INET;     
	addr.sin_port = htons(PORT);   
	addr.sin_addr = *((struct in_addr *)host->h_addr);
	bzero(&(addr.sin_zero), 8); 

	// lanzamos todas las tareas
	for (th = 0; th < MAX_THREADS; th++)
	{
		// identificado tarea
		args[th].thread_id = th;

		// ejecuta thread
		if (pthread_create(&threads[th], NULL, run, &args[th]))
			abort_("Error de creacion de hilo");
	}

	// espera a que terminen todas las tareas
	for (th = 0; th < MAX_THREADS; th++)
		if (pthread_join(threads[th], NULL))
			abort_("Error de cierre de hilo");
	
	return 0;
}
