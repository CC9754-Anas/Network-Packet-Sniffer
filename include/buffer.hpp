# pragma once

# include <iostream>
# include <string.h>

template <typename T>
class Buffer
{
    public:

        Buffer(std::size_t n) : n(n) {
            this->buff = new T[n];
            throw_if_null(this->buff,"cannot allocate memory for buffer");
        }

        /**
         * Implicitly assumes that size of _buff is n
        */
        Buffer(T* _buff,std::size_t n) {

            if(_buff == nullptr)
                std::invalid_argument("Cannot copy a buffer of null");

            this->buff = new T[n];
            this->n = n;
            throw_if_null(this->buff,"cannot allocate memory for buffer");

            auto dest = reinterpret_cast<void*>(this->buff);
            auto src  = reinterpret_cast<void*>(_buff);
            memcpy(dest,src,n);
        }

        Buffer(const Buffer<T> &_buff)
        {
            auto dest = reinterpret_cast<void*>(this->buff);
            auto src  = reinterpret_cast<void*>(_buff.buff);
            memcpy(dest,src,n);
        }

        T* get(){ return this->buff; }
    
    protected:

        T* buff = nullptr;
        std::size_t n = 0;

        void throw_if_null(T* _buff,const std::string &msg = "")
        {
            if(_buff == nullptr)
                throw std::runtime_error(msg);
        }
};