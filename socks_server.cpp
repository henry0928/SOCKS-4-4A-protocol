#include <cstdlib>
#include <iostream>
#include <memory>
#include <utility>
#include <sys/types.h>
#include <sys/wait.h>
#include <fstream>
#include <sstream> 
#include <boost/asio.hpp>

using namespace std ;
using boost::asio::ip::tcp;

struct client_info{
  string userid ;
  string source_ip ;
  string source_port ;
  string des_ip ;
  string des_port ;
};

struct firewall_node{
  string control ;
  string rule_ip ;
};

boost::asio::io_context io_context;

class server {
private:
  tcp::acceptor acceptor_;
  tcp::acceptor bind_acceptor ; 
  tcp::socket socket_;
  tcp::socket des_socket ;
  tcp::resolver resolver_ ;
  tcp::resolver test_resolver ;
  enum { max_length = 1024 };
  unsigned char data_[max_length];
  unsigned char des_buffer[65536] ;
  unsigned char sou_buffer[65536] ;
  unsigned char reply_buffer[8] ;
  unsigned short bind_port ;
  client_info user ;
public:
  server(boost::asio::io_context& io_context, short port)
    : acceptor_(io_context, tcp::endpoint(tcp::v4(), port)), bind_acceptor(io_context),
      socket_(io_context), des_socket(io_context), resolver_(io_context), test_resolver(io_context)
  {
    do_accept();
  }

  void do_accept() {
    acceptor_.async_accept(
        [this](boost::system::error_code ec, tcp::socket socket)
        {
          if (!ec) {
            socket_ = move(socket) ;
            start();
          } // if 

        });
  } // do_accept()

  void start() {
    do_read();
  } // start()

  void do_read() {
    socket_.async_read_some(boost::asio::buffer(data_, max_length),
        [this](boost::system::error_code ec, std::size_t length)
        {
          if (!ec) {
            io_context.notify_fork(boost::asio::io_context::fork_prepare) ;
            pid_t pid = fork() ;
            if ( pid == -1 )
              cerr << "fork error()\n" ;
            else if ( pid == 0 ) { // child process
              io_context.notify_fork(boost::asio::io_context::fork_child) ;
              if ( data_[0] == 4 ) { // its for SOCKS4 and SOCKS4A
                setup_user() ;
                if ( data_[1] == 1 ) { // connenct
                  if ( check_firewall( true ) == true ) {
                    print_info( true, true ) ;
                    do_connect() ;
                    reply( true, true ) ;
                    read_des() ;
                    read_sou() ;
                  } // if 
                  else {
                    reply( false, true ) ;
                    print_info( true, false ) ;
                    exit(0) ;
                  } // else      
                } // if
                else if ( data_[1] == 2 ) { // bind
                  if ( check_firewall( false ) == true ) {
                    print_info( false, true ) ;
                    do_bind() ;
                    reply( true, false ) ;
                    bind_acceptor.accept(des_socket) ; // should be block
                    reply( true, false ) ;
                    read_des() ;
                    read_sou() ;
                  } // if
                  else {
                    reply( false, true ) ; // just for reply do not care is bind or connect
                    print_info( false, false ) ;
                    exit(0) ;
                  } // else   
                } // else if 
              } // if
              else { // reject the request 
                reply( false, true ) ;
                exit(0) ;
              } // else

            } // else if 
            else { // parent process
              io_context.notify_fork(boost::asio::io_context::fork_parent) ;
              memset(data_, 0, max_length) ;
              socket_.close() ;
              do_accept() ;
            } // else   
          } // if 
        });
  } //do_read()

  bool check_firewall( bool is_connect ) {
    vector <firewall_node> c_control_list ;
    vector <firewall_node> b_control_list ;
    c_control_list.clear() ;
    b_control_list.clear() ; 
    fstream file_stream ;
    string str ;
    string access ;
    string type ;
    string rule ;
    firewall_node temp ;
    stringstream str_stream ; 
    tcp::resolver::query test_q(tcp::v4(), user.des_ip, user.des_port) ;
    tcp::resolver::iterator test_it = resolver_.resolve(test_q) ;
    user.des_ip = test_it->endpoint().address().to_string() ; // for translate dns to ip address
    file_stream.open( "socks.conf", ios::in ) ;
    if ( !file_stream ) 
      return false ;
    while ( getline( file_stream, str ) ) {
      str_stream << str ;
      str_stream >> access >> type >> rule ;
      temp.control = access ;
      temp.rule_ip = rule ;
      if ( type == "c" ) 
        c_control_list.push_back(temp) ;
      else 
        b_control_list.push_back(temp) ;
      str.clear() ;
      access.clear() ;
      type.clear() ;
      rule.clear() ;
      temp.control.clear() ;
      temp.rule_ip.clear() ;
      str_stream.str("") ; // this for str_stream to initial
      str_stream.clear() ; // this for str_stream to initial 
    } // while   
    file_stream.close() ;
    
    if ( is_connect == true )
      return check_rules(c_control_list) ;
    else 
      return check_rules(b_control_list) ;
  } // check_firewall()

  bool check_rules( vector<firewall_node> control_list ) {
    int i = 0 ;    
    int r_index = 0 ;
    int t_index = 0 ;
    int round = 0 ;
    int size ;
    string r_string ;
    string t_string ;
    size = control_list.size() ;
    while ( i < size ) {
      if ( control_list[i].control == "permit" ) {
        r_index = 0 ;
        t_index = 0 ;
        round = 0 ;
        while ( round < 4 ) {
          r_string.clear() ;
          t_string.clear() ;
          while ( control_list[i].rule_ip[r_index] != '.' && control_list[i].rule_ip[r_index] != '\0' ) {
            r_string = r_string + control_list[i].rule_ip[r_index] ;
            r_index = r_index + 1 ;
          } // while
          if ( control_list[i].rule_ip[r_index] != '\0' ) 
            r_index = r_index + 1 ; // escape '.'

          while ( user.des_ip[t_index] != '.' && user.des_ip[t_index] != '\0' ) {
            t_string = t_string + user.des_ip[t_index] ;
            t_index = t_index + 1 ;
          } // while 
          if ( user.des_ip[t_index] != '\0' )
            t_index = t_index + 1 ; //escape '.'

          if ( r_string == "*" )
            ; // do not need to compare 
          else if ( r_string != t_string )
            break ;
          else 
            ; // continue
            
          round = round + 1 ;
        } // while 
          
        if ( round == 4 )
          return true ;
      } // if
      i = i + 1 ;
    } // while

    return false ; 
  } // check_rules()
  
  void read_des() {
    //memset( des_buffer, 0, 65536 ) ;
    des_socket.async_read_some( boost::asio::buffer(des_buffer),
        [this](boost::system::error_code ec, size_t length)
        {
          if (!ec)
            write_sou(length) ;
          else {
            exit(0) ; 
          } // else   
        });
  } // read_des()

  void write_sou( size_t length ) {
    boost::asio::async_write(socket_, boost::asio::buffer(des_buffer, length),
        [this](boost::system::error_code ec, std::size_t /*length*/)
        {
          if (!ec) {
            //memset( des_buffer, 0, 65536 ) ;  
            read_des();
          } // if   
          else {
            exit(0) ; 
          } // else   
        });
  } // write_sou()

  void read_sou() {
    //memset( sou_buffer, 0, 65536 ) ; 
    socket_.async_read_some( boost::asio::buffer(sou_buffer),
        [this](boost::system::error_code ec, size_t length)
        {
          if (!ec)
            write_des(length) ;
          else {
            exit(0); 
          } // else   
        });
  } // read_sou()

  void write_des( size_t length ) {
    boost::asio::async_write(des_socket, boost::asio::buffer(sou_buffer, length),
        [this](boost::system::error_code ec, std::size_t /*length*/)
        {
          if (!ec) {
            //memset( des_buffer, 0, 65536 ) ;  
            read_sou();
          } // if   
          else {
            exit(0) ;
          } // else   
        });  
  } // write_des()

  void do_connect() {
    tcp::resolver::query q(tcp::v4(), user.des_ip, user.des_port) ;
    tcp::resolver::iterator it = resolver_.resolve(q) ;
    des_socket.connect(*it) ; 
  } // do_connect()

  void do_bind() {
    tcp::endpoint edp(boost::asio::ip::address::from_string("0.0.0.0"), 0) ;
    bind_acceptor.open(tcp::v4()) ;
    bind_acceptor.set_option(tcp::acceptor::reuse_address(true)) ;
    bind_acceptor.bind(edp) ;
    bind_acceptor.listen() ;
    bind_port = bind_acceptor.local_endpoint().port() ;
  } // do_bind()

  void reply( bool is_accept, bool is_connect ) {
    memset( reply_buffer, 0, 8 ) ;
    if ( is_connect == true ) {
      if ( is_accept == true )
        reply_buffer[1] = 90 ;
      else
        reply_buffer[1] = 91 ;
      boost::asio::write(socket_, boost::asio::buffer(reply_buffer, 8)) ;
    } // if 
    else {
      if ( is_accept == true )
        reply_buffer[1] = 90 ;
      else
        reply_buffer[1] = 91 ;
      reply_buffer[2] = bind_port / 256 ;
      reply_buffer[3] = bind_port % 256 ; 
      boost::asio::write(socket_, boost::asio::buffer(reply_buffer, 8)) ;
    } // else   
  } // reply()

  void setup_user() {
    char temp_des_ip[20] ;
    memset( temp_des_ip, 0, 20 ) ;
    int i = 8 ;
    int j = 0 ;
    int iter = 0  ;
    char temp_id[200] ;
    user.des_port = to_string( int(data_[2])*256 + int(data_[3]) ) ;
    if ( data_[4] == 0 && data_[5] == 0 && data_[6] == 0 ) {
      while ( data_[i] != '\0' )
        i++ ;
      i = i + 1 ; // to get first letter of Domain Name
      while ( data_[i] != '\0' ) {
        temp_des_ip[iter] = data_[i] ;
        iter = iter + 1 ;
        i = i + 1 ;
      } // while 
      temp_des_ip[iter] = '\0' ;
    } // if 
    else 
      sprintf( temp_des_ip, "%u.%u.%u.%u", data_[4], data_[5], data_[6], data_[7] ) ;
    user.des_ip = temp_des_ip ;
    while ( data_[i] != '\0' ) {
      temp_id[j] = data_[i] ;
      i++ ;
      j++ ;
    } // while
    temp_id[j] = '\0' ;
    user.userid = temp_id ;
    user.source_ip = socket_.remote_endpoint().address().to_string() ;
    user.source_port = to_string(socket_.remote_endpoint().port()) ; 
  } // setup_user()

  void print_info( bool is_connect, bool is_accept ) {
    cout << "<S_IP>: " << user.source_ip << "\n" ;
    cout << "<S_PORT>: " << user.source_port << "\n" ;
    cout << "<D_IP>: " << user.des_ip << "\n" ;
    cout << "<D_PORT>: " << user.des_port << "\n" ;
    if ( is_connect == true )
      cout << "<Command>: CONNECT"  << "\n" ;
    else 
      cout << "<Command>: BIND"  << "\n" ;
    if ( is_accept == true )
      cout << "<Reply>: Accept"  << "\n" ;
    else 
      cout << "<Reply>: Reject"  << "\n" ;
    cout << "\n" ;
    fflush(stdout) ;
  } // print_info()

}; // server()

int main(int argc, char* argv[])
{
  try
  {
    if (argc != 2)
    {
      std::cerr << "Usage: async_tcp_echo_server <port>\n";
      return 1;
    }

    //boost::asio::io_context io_context;

    server s(io_context, std::atoi(argv[1]));

    io_context.run();
  }
  catch (std::exception& e)
  {
    std::cerr << "Exception: " << e.what() << "\n";
  }

  return 0;
}