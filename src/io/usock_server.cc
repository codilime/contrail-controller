/*
 * The primary method implemented here is Send(), to transmit a
 * message over the Unix socket. It uses boost::asio::async_write to
 * send one message at a time over the socket, that is transmitted
 * asynchronously. The user can repeatedly call Send(). All those
 * buffers are tail-queued. Upon write_complete callback, the next
 * message from the front of the queue is sent.
 */
#include "usock_server.h"
#include <sys/wintypes.h>
using boost::asio::buffer_cast;
using boost::asio::buffer;
using boost::asio::mutable_buffer;

WindowsDomainSocketSession::~WindowsDomainSocketSession()
{
    if (observer_) {
        observer_(this, CLOSE);
    }

    /* Free up any remaining buffers in the queue. */
    for (BufferQueue::iterator iter = buffer_queue_.begin();
         iter != buffer_queue_.end(); ++iter) {
        DeleteBuffer(*iter);
    }
    buffer_queue_.clear();
}

void
WindowsDomainSocketSession::Start()
{
    if (observer_) {
        observer_(this, READY);
    }

    socket_.async_read_some(boost::asio::buffer(data_),
                            boost::bind(&WindowsDomainSocketSession::
                                        HandleRead, shared_from_this(),
                                        boost::asio::placeholders::error,
                                        boost::asio::placeholders::
                                        bytes_transferred));
}

void
WindowsDomainSocketSession::Send(const uint8_t * data, int data_len)
{
    if (!data || !data_len) {
        return;
    }
    bool write_now = buffer_queue_.empty();
    AppendBuffer(data, data_len);
    if (write_now) {
        WriteToSocket();
    }
}

void
WindowsDomainSocketSession::WriteToSocket()
{
    if (buffer_queue_.empty()) {
        return;
    }

    boost::asio::mutable_buffer head = buffer_queue_.front();
    boost::asio::async_write(socket_,
                             buffer(buffer_cast <const uint8_t *>(head),
                                    boost::asio::buffer_size(head)),
                             boost::bind(&WindowsDomainSocketSession::
                                         HandleWrite, shared_from_this(),
                                         boost::asio::placeholders::error));
}

void
WindowsDomainSocketSession::AppendBuffer(const uint8_t *src, int bytes)
{
    u_int8_t *data = new u_int8_t[bytes];
    memcpy(data, src, bytes);
    boost::asio::mutable_buffer buffer =
        boost::asio::mutable_buffer(data, bytes);
    buffer_queue_.push_back(buffer);
}

void
WindowsDomainSocketSession::DeleteBuffer(boost::asio::mutable_buffer buffer)
{
    const uint8_t *data = buffer_cast <const uint8_t *>(buffer);
    delete []data;
    return;
}

void
WindowsDomainSocketSession::HandleRead(const boost::system::error_code &error,
                                    size_t bytes_transferred)
{
    if (error) {
        return;
    }
    if (observer_) {
        observer_(this, READY);
    }
}

void
WindowsDomainSocketSession::HandleWrite(const boost::system::error_code &error)
{
    /*
     * async_write() is atomic in that it returns success once the entire message
     * is sent. If there is an error, it's okay to return from here so that the
     * session gets closed.
     */
    if (error) {
        return;
    }

    /*
     * We are done with the buffer at the head of the queue. Delete it.
     */
    DeleteBuffer(buffer_queue_.front());
    buffer_queue_.pop_front();

    /*
     * Write the next message, if there.
     */
    WriteToSocket();

    /*
     * Engage on the socket to keep it alive.
     */
    socket_.async_read_some(boost::asio::buffer(data_),
                            boost::bind(&WindowsDomainSocketSession::
                                        HandleRead, shared_from_this(),
                                        boost::asio::placeholders::error,
                                        boost::asio::placeholders::
                                        bytes_transferred));
}

UnixDomainSocketServer::UnixDomainSocketServer(boost::asio::io_service &io,
                                               const std::string &file)
  : io_service_(io),
   //WINDOWS-TEMP acceptor_(io, boost::asio::local::stream_protocol::endpoint(file)),
    session_idspace_(0)
{
    SessionPtr new_session(new WindowsDomainSocketSession(io_service_));
    //WINDOWS-TEMP acceptor_.async_accept(new_session->socket(),
                  //         boost::bind(&UnixDomainSocketServer::
                  //                     HandleAccept, this, new_session,
                 //                      boost::asio::placeholders::error));
}

void
UnixDomainSocketServer::HandleAccept(SessionPtr session,
                                     const boost::system::error_code &error)
{
    WindowsDomainSocketSession *socket_session = session.get();

    if (error) {
        if (observer_) {
            observer_(this, socket_session, DELETE_SESSION);
        }
        return;
    }

    socket_session->set_session_id(++session_idspace_);
    if (observer_) {
        observer_(this, socket_session, NEW_SESSION);
        session->Start();
    }

    SessionPtr new_session(new WindowsDomainSocketSession(io_service_));
   //WINDOWS-TEMP acceptor_.async_accept(new_session->socket(),
   //WINDOWS-TEMP                       boost::bind(&UnixDomainSocketServer::
   //WINDOWS-TEMP                                   HandleAccept, this, new_session,
   //WINDOWS-TEMP                                boost::asio::placeholders::error));
}
