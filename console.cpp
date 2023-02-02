#include <cstdlib>
#include <iostream>
#include <fstream>
#include <memory>
#include <utility>
#include <vector>
#include <sys/types.h>
#include <sys/wait.h>
#include <boost/asio.hpp>
#include <boost/algorithm/string/replace.hpp>

using namespace std ;
using boost::asio::ip::tcp;

struct client_info{
  char hostname[100] ;
  char port[10] ;
  char file[50] ;
} ;

vector<string> for_html_use ;  
client_info client[5] ;

void set_client_info( char* str, int index ) ;
void to_output_ip_port() ;
void parse_server_addr( char* str, string &ans ) ;

class session 
    : public enable_shared_from_this<session>
{
  private:
      vector<string>command_list ;
      tcp::resolver resolver_ ;
      tcp::socket socket_ ;
      tcp::resolver::query query_ ;
      enum { max_size = 15000 };
      char data[max_size] ;
      string output_buffer ;
      fstream file_stream ;
      string html_id ;
      string shell_command ;
      int index = 0 ;
      int client_id ;
      unsigned char reply_buffer[8] ;
  public:
      session(boost::asio::io_context& io_context, tcp::resolver::query q, string file, int id )
          :resolver_(io_context), socket_(io_context), query_(move(q))
          {
            depatch_id ( id ) ;
            client_id = id ;
            file_stream.open( file, ios::in ) ;
            if ( !file_stream )
              cerr << "can't open file!\n" ;
            shell_command.clear() ;
            while ( getline( file_stream, shell_command ) ) {
              command_list.push_back(shell_command) ;
              shell_command.clear() ;
            } // while   
            file_stream.close() ; 
          }

      void depatch_id( int id ) {
        if ( id == 0 )
          html_id = "s0" ;
        else if ( id == 1 ) 
          html_id = "s1" ;
        else if ( id == 2 ) 
          html_id = "s2" ;
        else if ( id == 3 ) 
          html_id = "s3" ;
        else if ( id == 4 ) 
          html_id = "s4" ;
      } // depatch_id()

      void start_connect(){
        auto self(shared_from_this()) ;
        resolver_.async_resolve( query_,
                    [this, self](boost::system::error_code ec, tcp::resolver::iterator it)
                    {
                      if (!ec)
                        resolve_handler(it) ;
                    }) ;
      } // start_connect()
  
      void resolve_handler(tcp::resolver::iterator it ) {
        auto self(shared_from_this()) ;
        socket_.async_connect(*it,
                  [this, self](boost::system::error_code ec)
                  {
                    if (!ec)
                      send_request() ;
                  }) ;
      } // resolver_handler()

      void send_request() {
        char host[100] ;
        strcpy( host, client[client_id].hostname ) ;
        unsigned char request[100] ;
        int i = 10 ; // from 10 start is domain name
        int j = 0 ; 
        memset( request, 0, 100 ) ;
        request[0] = 4 ;
        request[1] = 1 ;
        int port = atoi(client[client_id].port) ;
        request[2] = port / 256 ;
        request[3] = port % 256 ;
        request[7] = 1 ; // for socks 4a 
        request[8] = client_id + 1 ; // userid
        while ( host[j] != '\0' ) {
          request[i] = host[j] ;
          i = i + 1 ;
          j = j + 1 ; 
        } // while 
        auto self(shared_from_this()) ;
        boost::asio::async_write(socket_, boost::asio::buffer(request, 100),
                   [this, self](boost::system::error_code ec, std::size_t /*length*/)
                     {
                        if (!ec) {
                          receive_reply();
                        } // if 
                      });
      } // send_request()

      void receive_reply() {
        auto self(shared_from_this()) ;
        socket_.async_read_some( boost::asio::buffer(reply_buffer, 8),
                  [this, self](boost::system::error_code ec, size_t length)
                  {
                    if (!ec) {
                      if ( reply_buffer[1] == 90 )
                        do_read() ;
                      else 
                        cerr << "socks server reject!\n" ;
                    } // if 
                    else 
                      cerr << "ec is true\n" ;
                  });
      } // receive_reply() 
  
      void do_read() {
        auto self(shared_from_this()) ;
        socket_.async_read_some( boost::asio::buffer(data, max_size),
                  [this, self](boost::system::error_code ec, size_t length)
                  {
                    if (!ec) {
                      if ( check_percent() == true ) {
                        output_buffer = output_buffer + data ;  
                        memset( data, 0, max_size ) ;
                        output_shell( output_buffer ) ;
                        output_buffer.clear() ;
                        do_write() ;
                      } // if 
                      else {
                        output_buffer = output_buffer + data ;
                        memset( data, 0, max_size ) ;
                        output_shell( output_buffer ) ;
                        output_buffer.clear() ;
                        do_read() ;   
                      } // else 
                    } // if 
                    else 
                      cerr << "ec is true\n" ;
                  });
      } // do_read()

      void do_write() {
        string command ;
        command = clean_str( command_list[index] ) ;
        command = command + "\r\n" ;
        output_command( command ) ;
        index = index + 1 ;
        auto self(shared_from_this()) ;
        boost::asio::async_write(socket_, boost::asio::buffer(command, command.length()),
                   [this, self](boost::system::error_code ec, std::size_t /*length*/)
                     {
                        if (!ec) {
                          do_read();
                        } // if 
                      });
      } // do_write()

      string clean_str( string str ) {
        string new_str ;
        char temp[15000] ; 
        int j = 0 ;
        int i = 0 ;
        while ( str[i] != '\0') {
          if ( int(str[i]) >= 32 ) {
            temp[j] = str[i] ;
            j = j + 1 ;  
          } // if
          i = i + 1 ;
        } // while   
        temp[j] = '\0' ;
        new_str = temp ;
        return new_str ;
      } // clean_str

      bool check_percent() {
        for( int i = 0 ; i < max_size ; i++ ) {
          if ( data[i] == '%' )
            return true ; 
        } // for 

        return false ;
      } // check_jump()

      void output_command( string str ) {
        boost::algorithm::replace_all( str, "&", "&amp;" ) ;
        boost::algorithm::replace_all( str, "\"", "&quot;" ) ;
        boost::algorithm::replace_all( str, "\'", "&apos;" ) ;
        boost::algorithm::replace_all( str, "<", "&lt;" ) ;
        boost::algorithm::replace_all( str, ">", "&gt;" ) ;
        boost::algorithm::replace_all( str, "\r\n", "\n" ) ;
        boost::algorithm::replace_all( str, "\n", "<br>" ) ;
        cout << "<script>document.getElementById('" + html_id + "').innerHTML += '<b>" + str + "</b>';</script>" ;
        fflush(stdout) ; 
      } // output_command()

      void output_shell( string str ) {
        boost::algorithm::replace_all( str, "&", "&amp;" ) ;
        boost::algorithm::replace_all( str, "\"", "&quot;" ) ;
        boost::algorithm::replace_all( str, "\'", "&apos;" ) ;
        boost::algorithm::replace_all( str, "<", "&lt;" ) ;
        boost::algorithm::replace_all( str, ">", "&gt;" ) ;
        boost::algorithm::replace_all( str, "\r\n", "\n" ) ;
        boost::algorithm::replace_all( str, "\n", "<br>" ) ;
        cout << "<script>document.getElementById('" + html_id + "').innerHTML += '" + str + "';</script>" ;
        fflush(stdout) ; 
      } // output_shell()
} ; // session() 

int main( int argc, char* argv[], char* envp[] ) {
  boost::asio::io_context io_context ;
  const char* del = "&" ;
  int i = 0 ;
  char** str_list = (char**)malloc(sizeof(char*)*17) ; // for the hx px fx ...
  char query_string[1024] ;
  char* temp ; 
  strcpy( query_string, getenv("QUERY_STRING") ) ;
  //strcpy( query_string, "h0=127.0.0.1&p0=7777&f0=t2.txt&h1=127.0.0.1&p1=8888&f1=t3.txt&h2=&p2=&f2=&h3=&p3=&f3=&h4=&p4=&f4=&sh=127.0.0.1&sp=12345" ) ;
  temp = strtok( query_string, del ) ;
  while ( temp != NULL ) {
    str_list[i] = temp ;
    temp = strtok( NULL, del ) ;
    i = i + 1 ;
  } // while 
  
  i = 0 ;
  for ( int j = 0 ; j < 5 ; j++ ) {
    set_client_info(str_list[i], j) ;
    set_client_info(str_list[i+1], j) ;
    set_client_info(str_list[i+2], j) ;
    i = i + 3 ;
  } // for 
  // finish set client
  string server_addr ;
  string server_port ;
  parse_server_addr( str_list[15], server_addr ) ;
  parse_server_addr( str_list[16], server_port ) ;
  to_output_ip_port() ;
  string html_header = "Content-type: text/html\r\n\r\n" ;
  cout << html_header ;
  string html_content = R""""(
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8" />
                <title>NP Project 3 Sample Console</title>
                <link
                rel="stylesheet"
                href="https://cdn.jsdelivr.net/npm/bootstrap@4.5.3/dist/css/bootstrap.min.css"
                integrity="sha384-TX8t27EcRE3e/ihU7zmQxVncDAy5uIKz4rEkgIXeMed4M0jlfIDPvg6uqKI2xXr2"
                crossorigin="anonymous"
                />
                <link
                href="https://fonts.googleapis.com/css?family=Source+Code+Pro"
                rel="stylesheet"
                />
                <link
                rel="icon"
                type="image/png"
                href="https://cdn0.iconfinder.com/data/icons/small-n-flat/24/678068-terminal-512.png"
                />
                <style>
                * {
                    font-family: 'Source Code Pro', monospace;
                    font-size: 1rem !important;
                }
                body {
                    background-color: #212529;
                }
                pre {
                    color: #cccccc;
                }
                b {
                    color: #01b468;
                }
                </style>
            </head>
            <body>
                <table class="table table-dark table-bordered">
                <thead>
                    <tr>
                    <th scope="col">)"""" + for_html_use[0] + ":" + for_html_use[1] + "</th>" +
                    R"(<th scope="col">)" + for_html_use[2] + ":" + for_html_use[3] + "</th>" +
                    R"(<th scope="col">)" + for_html_use[4] + ":" + for_html_use[5] + "</th>" +
                    R"(<th scope="col">)" + for_html_use[6] + ":" + for_html_use[7] + "</th>" +
                    R"(<th scope="col">)" + for_html_use[8] + ":" + for_html_use[9] + "</th>" +
                    R"(</tr>
                </thead>
                <tbody>
                    <tr>
                    <td><pre id="s0" class="mb-0"></pre></td>
                    <td><pre id="s1" class="mb-0"></pre></td>
                    <td><pre id="s2" class="mb-0"></pre></td>
                    <td><pre id="s3" class="mb-0"></pre></td>
                    <td><pre id="s4" class="mb-0"></pre></td>
                    </tr>
                </tbody>
                </table>
            </body>
            </html>
        )";
  cout << html_content ;
  fflush(stdout) ;

  for ( int i = 0 ; i < 5 ; i++ ) {
    if ( strcmp( client[i].hostname, "" ) != 0 && strcmp( client[i].port, "" ) != 0 && strcmp( client[i].file, "" ) != 0 ) {
      string h(client[i].hostname) ;
      string p(client[i].port) ;
      string f(client[i].file) ;
      f = "test_case/" + f ;
      tcp::resolver::query q(server_addr, server_port) ;
      make_shared<session>(io_context, move(q), f, i)->start_connect() ;
    } // if 
  } // for 
  io_context.run() ;
  free(str_list) ;
} // main()

void parse_server_addr( char* str, string &ans ) {
  char temp_ans[50] ;
  int index = 0 ;
  int i = 0 ;
  while ( str[index] != '=' ) 
    index++ ;
  index = index + 1 ; // skip '='
  while ( str[index] != '\0' ) {
    temp_ans[i] = str[index] ;
    i++ ;
    index++ ;
  } // while
  temp_ans[i] = '\0' ;
  ans = temp_ans ;

} // parse_server_addr()

void to_output_ip_port() {
  string temp = client[0].hostname ;
  for_html_use.push_back(temp) ;
  temp = client[0].port ;
  for_html_use.push_back(temp) ;
  temp = client[1].hostname ;
  for_html_use.push_back(temp) ;
  temp = client[1].port ;
  for_html_use.push_back(temp) ;
  temp = client[2].hostname ;
  for_html_use.push_back(temp) ;
  temp = client[2].port ;
  for_html_use.push_back(temp) ;
  temp = client[3].hostname ;
  for_html_use.push_back(temp) ;
  temp = client[3].port ;
  for_html_use.push_back(temp) ;
  temp = client[4].hostname ;
  for_html_use.push_back(temp) ;
  temp = client[4].port ;
  for_html_use.push_back(temp) ;
} //to_output_ip_port()

void set_client_info( char* str, int index ) {
  int type = -1 ;
  if ( str[0] == 'h' )
    type = 0 ;
  else if ( str[0] == 'p' )
    type = 1 ;
  else if ( str[0] == 'f' )
    type = 2 ;
  else 
    return ;
  int i = 0 ;
  int j = 0 ;
  char temp_str[1024] ;
  memset( temp_str, 0, 1024) ;
  while ( str[i] != '=' )
    i++ ;
  i = i + 1 ; // skip the '='
  if ( str[i] != '\0' ) {
    while ( str[i] != '\0' ) {
      temp_str[j] = str[i] ;
      j = j + 1 ;
      i = i + 1 ;
    } // while 
    temp_str[j] = '\0';
    if ( type == 0 )
      strcpy( client[index].hostname, temp_str ) ;
    else if ( type == 1 )
      strcpy( client[index].port, temp_str ) ;
    else if ( type == 2 )
      strcpy( client[index].file, temp_str ) ;
  } // if 
  else {
    if ( type == 0 )
      strcpy( client[index].hostname, "" ) ;
    else if ( type == 1 )
      strcpy( client[index].port, "" ) ;
    else if ( type == 2 )
      strcpy( client[index].file, "" ) ;
  } // else 
    
} // set_client_info