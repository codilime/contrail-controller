/*
 * Implement a UNIX domain socket interface using boost::asio.
 */
#pragma once

#include <cstdio>
#include <iostream>
#include <list>
#include <boost/array.hpp>
#include <boost/bind.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/asio.hpp>
#include <boost/function.hpp>


class WindowsDomainSocketSession :
public boost::enable_shared_from_this<WindowsDomainSocketSession>
{
 public:
    static const int kPDULen = 4096;
    static const int kPDUHeaderLen = 4;
    static const int kPDUDataLen = 4092;

    enum Event
    {
        EVENT_NONE,
        READY,
        CLOSE
    };

    typedef boost::function <void (WindowsDomainSocketSession *, Event)>
      EventObserver;

    WindowsDomainSocketSession (boost::asio::io_service &io_service)
        : socket_(io_service), session_id_(0)
    {
    }

    ~WindowsDomainSocketSession();

    boost::asio::generic::stream_protocol::socket &socket()
    {
        return socket_;
    }

    void
    set_observer(EventObserver observer)
    {
        observer_ = observer;
    }

    uint64_t
    session_id()
    {
        return session_id_;
    }

    void
    set_session_id(uint64_t id)
    {
        session_id_ = id;
    }

    void Start();
    void Send(const uint8_t * data, int data_len);

 private:
    typedef std::list <boost::asio::mutable_buffer> BufferQueue;

    void WriteToSocket();
    void AppendBuffer(const uint8_t * data, int len);
    void DeleteBuffer(boost::asio::mutable_buffer);
    void HandleRead(const boost::system::error_code & error, size_t bytes);
    void HandleWrite(const boost::system::error_code & error);

    boost::asio::generic::stream_protocol::socket socket_;
    BufferQueue buffer_queue_;
    uint8_t data_[kPDULen];
    EventObserver observer_;
    uint64_t session_id_;
};

typedef boost::shared_ptr <WindowsDomainSocketSession> SessionPtr;

class UnixDomainSocketServer
{
 public:

    enum Event
    {
        EVENT_NONE,
        NEW_SESSION,
        DELETE_SESSION
    };

    typedef boost::function <void (UnixDomainSocketServer *,
                                   WindowsDomainSocketSession *, Event) >
      EventObserver;

    UnixDomainSocketServer(boost::asio::io_service &io_service,
                           const std::string &file);

    void HandleAccept(SessionPtr new_session,
                      const boost::system::error_code &error);

    void set_observer(EventObserver observer)
    {
        observer_ = observer;
    }

 private:
    boost::asio::io_service &io_service_;
    EventObserver observer_;
   //WINDOWS-TEMP boost::asio::generic::stream_protocol::acceptor acceptor_;
    uint64_t session_idspace_;
};
