#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
//IPv6
#include <netdb.h>
#include <netax25/ax25.h>
#include <netrose/rose.h>
#include <netax25/axlib.h>
#include <netax25/axconfig.h>
#include <netax25/nrconfig.h>
#include <netax25/rsconfig.h>
#include <netax25/procutils.h>

#include "node.h"

ax25io *NodeIo  = NULL;

void node_prompt();

int aliascmd = 0;

/*
 * Do some validity checking for callsign pointed to by `s'.
 */
static int check_call(const char *s)
{
  int len = 0;
  int nums = 0;
  int ssid = 0;
  char *p[1];

  if (s == NULL)
    return -1;
  while (*s && *s != '-') {
    if (!isalnum(*s))
      return -1;
    if (isdigit(*s))
      nums++;
    len++;
    s++;
  }
  if (*s == '-') {
    if (!isdigit(*++s))
      return -1;
    ssid = strtol(s, p, 10);
    if (**p)
      return -1;
  }
  if (len < 4 || len > 6 || !nums || nums > 2 || ssid < 0 || ssid > 15)
    return -1;
  return 0;
}

static void alarm_handler(int sig)
{
  axio_eolmode(NodeIo, EOLMODE_TEXT);
  axio_puts("\n",NodeIo);
  if (check_perms(PERM_ANSI, 0L) != -1) {
    axio_printf(NodeIo,"\e[05;31m");
  }
  if (User.ul_type == AF_NETROM) {
    node_msg("%s} Inactivity timeout! Closing circuit... ", NodeId);
  }
  if ((User.ul_type == AF_AX25) || (User.ul_type == AF_ROSE)) {
    node_msg("Inactivity timeout! Disconnecting you... ");
  }
  if ((User.ul_type ==  AF_INET) || (User.ul_type == AF_INET6)) {
    node_msg("Inactivity timeout! Disconnecting you...");
  }
  if ((User.ul_type == AF_INET) || (User.ul_type == AF_INET6)) {
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo,"\e[0;m");
    }
  }
  node_logout("User timed out"); 
}

static void term_handler(int sig)
{
  axio_eolmode(NodeIo, EOLMODE_TEXT);
  if (User.ul_type == AF_NETROM) {
    node_msg("%s} Termination received!", NodeId);
  } else {
    node_msg("%s - System going down! Disconnecting...", FlexId);
  }
  node_logout("SIGTERM");
}

static void quit_handler(int sig)
{
  axio_eolmode(NodeIo, EOLMODE_TEXT);
  node_logout("User terminated at remote");
}

static int
uronode_init(void)
{
#ifdef HAVE_AX25
  if (ax25_config_load_ports() == 0) {
    node_log(LOGLVL_ERROR, "No AX.25 port data configured");
    return 1;
  }
#endif	

#ifdef HAVE_NETROM
  nr_config_load_ports();
#endif	

#ifdef HAVE_ROSE			
  rs_config_load_ports();
#endif

  return 0;
}

int main(int argc, char *argv[])
{
  struct sockaddr_storage saddr;  
  int i;
  socklen_t slen = sizeof(saddr);

  if (sizeof(saddr) < sizeof(struct full_sockaddr_ax25)) {
    printf("ouch.  saddr_storage is too small.");
    exit(2);
  }
#ifdef HAVEMOTD
  char *p, buf[256], *pw;
#else
  char *p, *pw;
#endif
  int paclen;
#ifdef HAVEMOTD
  FILE *fp;
#endif
  int invalid_cmds = 0;
  int no_password = 2;
  int first_time = 1; 
 	
  signal(SIGALRM, alarm_handler);
  signal(SIGTERM, term_handler);
  signal(SIGPIPE, quit_handler);
  signal(SIGQUIT, quit_handler);

  if (uronode_init()) {
    exit(1);
  }
  slen = sizeof(saddr);
  if (getpeername(STDOUT_FILENO, (struct sockaddr *)&saddr, &slen) == -1) {
    if (errno != ENOTSOCK) {
      node_log(LOGLVL_ERROR, "getpeername: %s", strerror(errno));
      return 1;
    }
    User.ul_type = AF_UNSPEC;
  } else {
    User.ul_type = saddr.ss_family;
  }
  switch (User.ul_type) {
  case AF_FLEXNET:
  case AF_AX25: {
    struct full_sockaddr_ax25 *sax = (struct full_sockaddr_ax25 *)&saddr;
    strcpy(User.call, ax25_ntoa(&(sax->fsa_ax25.sax25_call)));
    slen = sizeof(saddr);
    if (getsockname(STDOUT_FILENO, (struct sockaddr *)&saddr, &slen) == -1) {
      node_log(LOGLVL_ERROR, "getsockname: %s", strerror(errno));
      return 1;
    }
    strcpy(User.ul_name, ax25_config_get_port(&(sax->fsa_digipeater[0])));
    paclen = ax25_config_get_paclen(User.ul_name);
    p = AX25_EOL;
    break;
  }
  case AF_NETROM: {
    struct full_sockaddr_ax25 *sax = (struct full_sockaddr_ax25 *)&saddr;

    strcpy(User.call, ax25_ntoa(&sax->fsa_ax25.sax25_call));
    strcpy(User.ul_name, ax25_ntoa(&sax->fsa_digipeater[0]));

    slen = sizeof(saddr);
    if (getsockname(STDOUT_FILENO, (struct sockaddr *)&saddr, &slen) == -1) {
      node_log(LOGLVL_ERROR, "getsockname: %s", strerror(errno));
      return 1;
    }
    strcpy(User.ul_port, nr_config_get_port(&sax->fsa_ax25.sax25_call));
    paclen = nr_config_get_paclen(User.ul_port);
    p = NETROM_EOL;
    break;
  }
#ifdef HAVE_ROSE
  case AF_ROSE:
  {
    struct sockaddr_rose *srose = (struct sockaddr_rose *)&saddr;
    strcpy(User.call, ax25_ntoa(&srose->srose_call));
    strcpy(User.ul_name, rose_ntoa(&srose->srose_addr));
    paclen = rs_config_get_paclen(NULL);
    p = ROSE_EOL;
    break;
  }
#endif		
  case AF_INET:
  {
    struct sockaddr_in *sin4 = (struct sockaddr_in *)&saddr;
    inet_ntop(saddr.ss_family, &sin4->sin_addr, User.ul_name, 32);
    paclen = 1024;
    p = INET_EOL;
    break;
  }
  case AF_INET6:
  {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&saddr;
    inet_ntop(saddr.ss_family, &(sin6->sin6_addr), User.ul_name, 32);
    paclen = 1024;
    p = INET_EOL;
    break;
  }
  default:
  case AF_UNSPEC:
    strcpy(User.ul_name, "local");
    p = get_call(getuid());
    if (NULL == p) {
      node_log(LOGLVL_ERROR, "No uid->callsign association found", -1);
      printf("Launching: telnet localhost 3694 ...\n");
      printf("if this fails please RTFM to see how to properly configure it.\n  - 73 de N1URO\a\n"); 
      node_log(LOGLVL_ERROR, "Tool ran me from the console so I'm forcing", -1);
      node_log(LOGLVL_ERROR, "a telnet session to port 3694/tcp on them.", -1);
      if(NodeIo!=NULL) {
	      axio_flush(NodeIo);
      }
      if (system("telnet localhost 3694") < 0 ) {                        /* VE3TOK - 18Nov2014, return value */
        syslog(LOG_DEBUG, "Can't \"execute telnet ::1 or 127.0.0.1 3694\"");
        return 1;
      }
      node_log(LOGLVL_ERROR,"Closing console telnet session.", -1);
      return -1;
    }
    strcpy(User.call, p);
    paclen = 1024;
    p = UNSPEC_EOL;
    break;
  }
  NodeIo = axio_init(STDIN_FILENO, STDOUT_FILENO, paclen, p);
  if (NodeIo == NULL) {
    node_log(LOGLVL_ERROR, "Error initializing I/O");
    return 1;
  }
#ifdef HAVE_ZLIB_H
  if (argc > 1 && strcmp(argv[1], "-c") == 0) {
    axio_compr(NodeIo, 1);
  }
#endif
  if ((User.ul_type == AF_INET) || (User.ul_type == AF_INET6)) {
    axio_tnmode(NodeIo, 1);
    axio_tn_do_linemode(NodeIo);
  }
  init_nodecmds();
  if (read_config() == -1) {
    axio_end(NodeIo);
    return 1;
  }
  for(i=1;i<argc;i++) {
    if (strcmp(argv[i],"--delay")==0) {
      axio_flush(NodeIo);
      p = axio_getline(NodeIo);
    }
  }
  User.state = STATE_LOGIN;
  login_user();
  if (User.call[0] == 0) {
    axio_printf(NodeIo,"(%s:uronode) login: ", HostName);
    axio_flush(NodeIo);
    alarm(180L);		/* 3 min timeout */
    if ((p = axio_getline(NodeIo)) == NULL)
      node_logout("User disconnected");
    alarm(0L);
    strncpy(User.call, p, 9);
    User.call[9] = 0;
    strlwr(User.call);
  }
  if ((p = strstr(User.call, "-0")) != NULL)
    *p = 0;
  if (check_call(User.call) == -1) {
    node_msg("%s - Invalid callsign", FlexId);
    node_log(LOGLVL_LOGIN, "Invalid callsign %s @ %s", User.call, User.ul_name);
    node_logout("Invalid callsign");
  }
  if ((pw = read_perms(&User, (const struct sockaddr *)&saddr)) == NULL) {
    node_msg("Sorry, I'm not allowed to talk to you.");
    axio_printf(NodeIo,"*** Password required! If you don't have a password please email\n%s for a password you wish to use.\n", Email);
    node_log(LOGLVL_LOGIN, "Login denied for %s @ %s", User.call, User.ul_name);
    node_logout("Login denied");
  } 
    else if  (User.ul_type == AF_AX25 || User.ul_type == AF_NETROM || User.ul_type == AF_ROSE) {
	(strcmp(pw, "*") == 0);
    }
    else if (strcmp(pw, "*") != 0) {
    axio_printf(NodeIo,"*** Password required! If you don't have a password please email\n%s for a password you wish to use.", Email);
    axio_printf(NodeIo,"\nPassword: ");
    if ((User.ul_type == AF_INET) || (User.ul_type == AF_INET6)) {
      axio_tn_will_echo(NodeIo);
      axio_eolmode(NodeIo, EOLMODE_BINARY);
    }
    axio_flush(NodeIo);
    p = axio_getline(NodeIo);
    if ((User.ul_type == AF_INET) || (User.ul_type == AF_INET6)) {
      axio_tn_wont_echo(NodeIo);
      axio_eolmode(NodeIo, EOLMODE_TEXT);
      /*			axio_puts("\n",NodeIo); */
    }
   if ((User.ul_type == AF_NETROM) && (strcmp(p, pw) == 0)) {
      node_msg("%s} Welcome.", NodeId);
   }
    if (p == NULL || strcmp(p, pw) != 0) {
      axio_printf(NodeIo, "\n");
      if (User.ul_type == AF_NETROM) {
	node_msg("%s} Invalid or incorrect password...", NodeId);
      } else {
	node_msg("%s Invalid or incorrect password...", FlexId);
      }
      node_log(LOGLVL_LOGIN, "Login failed for %s @ %s", User.call, User.ul_name);
      node_logout("Login failed");
    }
    no_password = 0;
  };
  free(pw);
  examine_user();
  ipc_open();
  node_log(LOGLVL_LOGIN, "%s @ %s logged in", User.call, User.ul_name);
#ifdef HAVEMOTD
  if (User.ul_type == AF_NETROM) {
    /*		axio_printf(NodeIo, "%s} Welcome.\n", NodeId);  */
  } else 
    if ((User.ul_type == AF_INET) || (User.ul_type == AF_INET6)) {
      if (check_perms(PERM_ANSI, 0L) != -1) { 
	node_msg("\n\e[01;34m[\e[01;37m%s\e[01;34m]\e[0m\nWelcome %s to the %s packet shell.", VERSION, User.call, HostName);
      } else if (check_perms(PERM_ANSI, 0L) == -1) {
	node_msg("\n[%s]\nWelcome %s to the %s packet shell.", VERSION, User.call, HostName);
      }
      if ((fp = fopen(HAVEMOTD, "r")) != NULL) {
	while (fgets(buf,256, fp) != NULL) axio_puts(buf,NodeIo);
	axio_printf (NodeIo, "\n");
/*	axio_flush(NodeIo); */
      }
    } else if (User.ul_type == AF_AX25) { 
      if (check_perms(PERM_ANSI, 0L) != -1) {
	node_msg("\e[01;34m[\e[01;37m%s\e[01;34m]\e[0m - Welcome to %s", VERSION, FlexId);
      } else
	node_msg("%s - Welcome to %s", VERSION, FlexId); 
      if ((fp = fopen(HAVEMOTD, "r")) != NULL) {
	while (fgets(buf, 256, fp) != NULL) axio_puts(buf,NodeIo);
	axio_puts ("\n",NodeIo);
/*	axio_flush(NodeIo); */
      } 
    } else if (User.ul_type == AF_ROSE) {
	node_msg("%s - Welcome to %s", VERSION, RoseId);
        if ((fp = fopen(HAVEMOTD, "r")) != NULL) {
        while (fgets(buf, 256, fp) != NULL) axio_puts(buf,NodeIo);
        axio_puts ("\n",NodeIo);
/*        axio_flush(NodeIo); */
      }      
    }
  lastlog();
#endif
  axio_flush(NodeIo);
  while (1) { if (User.ul_type != AF_NETROM) {
      axio_flush(NodeIo);
      if (check_perms(PERM_ANSI, 0L) != -1) {
	axio_printf(NodeIo,"\e[01;34m");
      }
      if (no_password == 2) 	{ 
	node_prompt();
      }
      if (no_password == 1) 	{
	node_prompt();
	no_password = 2;
      }
      if (no_password == 0) 
	{
	  if (first_time == 1) 
	    {
	      first_time = 0;
	      if (User.ul_type != AF_NETROM) {
		/* node_prompt("3"); */
		if ((User.ul_type == AF_AX25) || (User.ul_type == AF_ROSE)) {
		  node_prompt();
		}
	      }
	    }
	  else if ((User.ul_type != AF_NETROM) && (User.ul_type != AF_ROSE)) {
	    node_prompt();
	  } else if ((User.ul_type == AF_NETROM) || (User.ul_type == AF_ROSE)) {
	    axio_printf(NodeIo,"\n");
	  }
	}
    }
    if (check_perms(PERM_ANSI, 0L) != -1) {
      /* Not needed from what I see so far.        */
      if (User.ul_type == AF_AX25) {
	axio_printf(NodeIo,"\e[0m"); 
      }
    }
    axio_flush(NodeIo); 
    User.state = STATE_IDLE;
    time(&User.cmdtime);
    update_user();
    alarm(IdleTimeout);
    errno = 0;
    if ((p = axio_getline(NodeIo)) == NULL) {
      if (errno == EINTR)
	continue;
      node_logout("User disconnected");
    };
    alarm(IdleTimeout);
    errno = 0;
    time(&User.cmdtime);
    update_user();
    aliascmd = 0;
    switch (cmdparse(Nodecmds, p))
      {
      case -1: 
	if (++invalid_cmds < 3) {
	  /* 			node_msg("%s Unknown command. Type ? for a list", NodeId); */
	  if (User.ul_type == AF_NETROM) {
	    node_msg("What?\007"); 
	  } else if (User.ul_type == AF_ROSE) {
	    axio_printf(NodeIo,"Que?\007");
	  } else if ((User.ul_type == AF_INET) || (User.ul_type == AF_INET6)) {
	    axio_printf(NodeIo, "Huh?\007");
	  } else {
	    axio_printf(NodeIo,"Eh?\007");
	  }
	  node_log(LOGLVL_ERROR,"%s Tool tried bogus command", NodeId);
	}
	else 	{
	  if (User.ul_type == AF_NETROM) {
	    node_msg("%s} Too many invalid commands. Disconnecting...", NodeId);
	    node_logout("Too many invalid commands");
	  } else {
	    node_msg("Too many invalid commands, disconnecting you...");
	    node_logout("Too many invalid commands");
	  }
	}
	break;
      case 0: 
	invalid_cmds = 0;
	/*			axio_puts ("\n",NodeIo); */
	break;
      case 1:
	invalid_cmds = 0;
	break;
      case 2: 
	invalid_cmds = 0;
	break;
      }
  }
  node_logout("Out of main loop !?!?!?");
}
