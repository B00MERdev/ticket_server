#include <iostream>
#include <utility>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <vector>
#include <fstream>
#include <unordered_set>
#include <unordered_map>
#include <chrono>
#include <endian.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#define DECIMAL_BASE 10

#define DEFAULT_CHAR '0'

#define FILE_FLAG "-f"
#define PORT_FLAG "-p"
#define TIMEOUT_FLAG "-t"

#define BUFFER_SIZE_IN_BYTES 65507

#define GET_EVENTS_ID 1
#define GET_RESERVATION_ID 3
#define GET_TICKETS_ID 5
#define EVENTS_ID 2
#define RESERVATION_ID 4
#define TICKETS_ID 6
#define BAD_REQUEST_ID 255

#define DEFAULT_PORT 2022
#define MIN_PORT 0
#define MAX_PORT 65535

#define DEFAULT_TIMEOUT 5
#define MIN_TIMEOUT 1
#define MAX_TIMEOUT 86400

#define MIN_EVENT_ID 0
#define MAX_EVENT_ID 999999

#define MIN_RESERVATION_ID 1000000

#define COOKIE_LENGTH_IN_BYTES 48
#define TICKET_LENGTH_IN_BYTES 7

#define COOKIE_CHAR_MIN 33
#define COOKIE_CHAR_MAX 126

#define TICKET_CHAR_MIN 55
#define TICKET_CHAR_MAX 90
#define TICKET_GAP 7

using message_id_t = uint8_t; // 1 oktet, pole binarne;
using description_length_t = uint8_t; // 1 oktet, pole binarne, liczba oktetów w polu description;
using description_t = std::string; // opis wydarzenia, dowolny niepusty tekst, niezawierający znaku o kodzie zero ani znaku przejścia do nowej linii;
using ticket_count_t = uint16_t; //2 oktety, pole binarne;
using event_id_t = uint32_t; // 4 oktety, pole binarne, unikalny identyfikator wydarzenia, generowany przez serwer, wartość z zakresu od 0 do 999999;
using reservation_id_t = uint32_t; // 4 oktety, pole binarne, unikalny identyfikator rezerwacji, generowany przez serwer, wartość większa niż 999999;
using cookie_t = std::string; // 48 oktetów, znaki ASCII o kodach z zakresu od 33 do 126, unikalny, trudny do odgadnięcia napis potwierdzający rezerwację, generowany przez serwer;
using expiration_time_t = uint64_t; // 8 oktetów, pole binarne, liczba sekund od początku epoki uniksa;
using ticket_t = std::string; // 7 oktetów, znaki ASCII, tylko cyfry i wielkie litery alfabetu angielskiego, unikalny kod biletu, generowany przez serwer.

using response_id_t = uint32_t;

const size_t get_events_length = sizeof(message_id_t);
const size_t get_reservation_length = sizeof(message_id_t) + sizeof(event_id_t) + sizeof(ticket_count_t);
const size_t get_tickets_length = sizeof(message_id_t) + sizeof(reservation_id_t) + sizeof(char) * COOKIE_LENGTH_IN_BYTES;

expiration_time_t get_seconds_since_epoch()
{
    // get the current time
    const auto now     = std::chrono::system_clock::now();

    // transform the time into a duration since the epoch
    const auto epoch   = now.time_since_epoch();

    // cast the duration into seconds
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(epoch);

    // return the number of seconds
    return (expiration_time_t)seconds.count();
}

char random_cookie_char() {
    return (char)(COOKIE_CHAR_MIN + rand() % (COOKIE_CHAR_MAX - COOKIE_CHAR_MIN + 1));
}

char random_ticket_char() {
    char res = (char)(TICKET_CHAR_MIN + rand() % (TICKET_CHAR_MAX - TICKET_CHAR_MIN + 1));
    if (res < 65) res -= TICKET_GAP;
    return res;
}

class Event {
public:
    description_length_t description_length;
    description_t description;

    Event(description_length_t d_length, description_t desc) :
    description_length(d_length), description(std::move(desc)) {};

    Event() {
        description_length = 0;
        description = "";
    };
};

using events_content_map_t = std::unordered_map<event_id_t , Event>;
using events_t_count_map_t = std::unordered_map<event_id_t , ticket_count_t>;

class Reservation {
public:
    event_id_t event_id;
    ticket_count_t ticket_count;
    cookie_t cookie;
    expiration_time_t expiration_time;
    std::vector<ticket_t> tickets;
    bool tickets_acquired = false;

    Reservation(event_id_t e_id, ticket_count_t t_count, cookie_t input_cookie, expiration_time_t e_time) :
    event_id(e_id), ticket_count(t_count), cookie(std::move(input_cookie)), expiration_time(e_time) {
        tickets = std::vector<ticket_t>();
    };
};

using reservation_map_t = std::unordered_map<reservation_id_t, Reservation>;

//GET_RESERVATION – message_id = 3, event_id, ticket_count > 0, prośba o zarezerwowanie wskazanej liczby biletów na wskazane wydarzenia;
class Get_reservation {
public:
    event_id_t event_id;
    ticket_count_t ticket_count;

    explicit Get_reservation(message_id_t* raw_net_data) {
        raw_net_data++;
        auto* event_id_pointer = (event_id_t*) raw_net_data;
        event_id = ntohl(*event_id_pointer);
        event_id_pointer++;
        auto* ticket_count_pointer = (ticket_count_t*) event_id_pointer;
        ticket_count = ntohs(*ticket_count_pointer);
    }
};

//GET_TICKETS – message_id = 5, reservation_id, cookie, prośba o wysłanie zarezerwowanych biletów.
class Get_tickets {
public:
    reservation_id_t reservation_id;
    cookie_t cookie;

    explicit Get_tickets(message_id_t* raw_net_data) {
        raw_net_data++;
        auto* reservation_id_pointer = (reservation_id_t*) raw_net_data;
        reservation_id = ntohl(*reservation_id_pointer);
        reservation_id_pointer++;

        auto* next_char_pointer = (char*) reservation_id_pointer;
        cookie = std::string(COOKIE_LENGTH_IN_BYTES, DEFAULT_CHAR);
        for (size_t i = 0; i < COOKIE_LENGTH_IN_BYTES; ++i) {
            cookie[i] = *next_char_pointer;
            next_char_pointer++;
        }
    }
};

//EVENTS – message_id = 2, powtarzająca się sekwencja pól event_id, ticket_count, description_length, description,
// odpowiedź na komunikat GET_EVENTS zawierająca listę opisów wydarzeń i liczb dostępnych biletów na każde wydarzenie;
class Events_output {
public:
    message_id_t message_id = EVENTS_ID;
    events_content_map_t events_content;
    events_t_count_map_t events_t_count;

    explicit Events_output(events_content_map_t ev_c, events_t_count_map_t ev_t_c) :
    events_content(std::move(ev_c)), events_t_count(std::move(ev_t_c)) {};

    void write_raw_data_to_buffer(message_id_t * buff, size_t* length) {
        size_t counter = sizeof(message_id_t);
        *buff = message_id;
        buff++;

        for (event_id_t i = 0; i < events_content.size(); ++i) {
            auto event = events_content[i];
            auto ticket_count = events_t_count[i];
            counter += sizeof(event_id_t) + sizeof(ticket_count_t) + sizeof(event.description_length) +
                    event.description_length * sizeof(char);
            if (counter > BUFFER_SIZE_IN_BYTES) {
                break;
            } else {
                *length = counter;
            }
            auto* next_event_id = (event_id_t*)buff;
            *next_event_id = htonl(i);
            next_event_id++;
            auto* next_ticket_count = (ticket_count_t*)next_event_id;
            *next_ticket_count = htons(ticket_count);
            next_ticket_count++;
            auto* next_description_length = (description_length_t*)next_ticket_count;
            *next_description_length = event.description_length;
            next_description_length++;
            auto* next_char = (char*)next_description_length;
            for (size_t j = 0; j < event.description_length; ++j) {
                *next_char = event.description[j];
                next_char++;
            }
            buff = (message_id_t*)next_char;
        }
    }
};

//RESERVATION – message_id = 4, reservation_id, event_id, ticket_count, cookie,
// expiration_time, odpowiedź na komunikat GET_RESERVATION potwierdzająca rezerwację,
// zawierająca czas, do którego należy odebrać zarezerwowane bilety;
class Reservation_output {
public:
    message_id_t message_id = RESERVATION_ID;
    reservation_id_t reservation_id;
    event_id_t event_id;
    ticket_count_t ticket_count;
    cookie_t cookie;
    expiration_time_t expiration_time;

    Reservation_output(reservation_id_t r_id, event_id_t e_id, ticket_count_t t_count, cookie_t input_cookie, expiration_time_t e_time) :
    reservation_id(r_id), event_id(e_id), ticket_count(t_count), cookie(std::move(input_cookie)), expiration_time(e_time) {};

    void write_raw_data_to_buffer(message_id_t * buff, size_t* length) {
        *length = sizeof(message_id_t) + sizeof(reservation_id_t) + sizeof(event_id_t) +
                sizeof(ticket_count_t) + sizeof(char) * COOKIE_LENGTH_IN_BYTES + sizeof(expiration_time_t);
        *buff = message_id;
        buff++;
        auto* res_id = (reservation_id_t*)buff;
        *res_id = htonl(reservation_id);
        res_id++;
        auto* e_id = (event_id_t*)res_id;
        *e_id = htonl(event_id);
        e_id++;
        auto* t_count = (ticket_count_t*)e_id;
        *t_count = htons(ticket_count);
        t_count++;
        auto* next_char = (char*)t_count;
        for (size_t i = 0; i < COOKIE_LENGTH_IN_BYTES; ++i) {
            *next_char = cookie[i];
            next_char++;
        }
        auto* e_time = (expiration_time_t*)next_char;
        *e_time = htobe64(expiration_time);
    }
};

//TICKETS – message_id = 6, reservation_id, ticket_count > 0, ticket, …, ticket, odpowiedź na komunikat GET_TICKETS zawierająca ticket_count pól typu ticket;
class Tickets_output{
public:
    message_id_t message_id = TICKETS_ID;
    reservation_id_t reservation_id;
    ticket_count_t ticket_count;
    std::vector<ticket_t> tickets;

    Tickets_output(reservation_id_t r_id, ticket_count_t t_count, std::vector<ticket_t> input_tickets) :
    reservation_id(r_id), ticket_count(t_count), tickets(std::move(input_tickets)) {};

    void write_raw_data_to_buffer(message_id_t * buff) {
        *buff = message_id;
        buff++;
        auto* r_id = (reservation_id_t*)buff;
        *r_id = htonl(reservation_id);
        r_id++;
        auto* t_count = (ticket_count_t*)r_id;
        *t_count = htons(ticket_count);
        t_count++;
        auto* next_char = (char*)t_count;
        for (size_t i = 0; i < ticket_count; ++i) {
            for (int j = 0; j < TICKET_LENGTH_IN_BYTES; ++j) {
                *next_char = tickets[i][j];
                next_char++;
            }
        }
    }
};

//BAD_REQUEST – message_id = 255, event_id lub reservation_id, odmowa na prośbę zarezerwowania biletów GET_RESERVATION lub wysłania biletów GET_TICKETS.
class Bad_request_output{
public:
    message_id_t message_id = BAD_REQUEST_ID;
    response_id_t response_id;

    explicit Bad_request_output(response_id_t r_id) : response_id(r_id) {};

    void write_raw_data_to_buffer(message_id_t * buff, size_t* length) {
        *length = sizeof(message_id_t) + sizeof(response_id);
        *buff = message_id;
        buff++;
        auto* r_id = (response_id_t*)buff;
        *r_id = htonl(response_id);
    }
};

void set_flags(int argc, char* argv[], const char **file_name, unsigned long& port, unsigned long& timeout) {
    if (argc % 2 == 0) {
        std::cerr << "Invalid number of arguments!" << std::endl;
        exit(1);
    }

    int counter = 1;
    bool file_flag_present = false;

    while (counter < argc) {
        std::string argument = (std::string) argv[counter];
        const char* next_argument = argv[counter + 1]; // safe because argc % 2 is 1

        counter += 2;

        if (argument == FILE_FLAG) {
            file_flag_present = true;
            *file_name = next_argument;
        } else if (argument == PORT_FLAG) {
            try {
                port = std::stoul(next_argument, nullptr, DECIMAL_BASE);
            } catch (std::exception& exception) {
                std::cerr << "Port has to be a number!" << std::endl;
                exit(1);
            }

            if (MIN_PORT > port || MAX_PORT < port) {
                std::cerr << "Invalid port value!" << std::endl;
                exit(1);
            }
        } else if (argument == TIMEOUT_FLAG) {
            try {
                timeout = std::stoul(next_argument, nullptr, DECIMAL_BASE);
            } catch (std::exception& exception) {
                std::cerr << "Timeout has to be a number!" << std::endl;
                exit(1);
            }

            if (MIN_TIMEOUT > timeout || MAX_TIMEOUT < timeout) {
                std::cerr << "Invalid timeout value!" << std::endl;
                exit(1);
            }
        } else {
            std::cerr << "Invalid argument!" << std::endl;
            exit(1);
        }
    }

    if (!file_flag_present) {
        std::cerr << "No file flag!" << std::endl;
        exit(1);
    }

    struct stat buf{};
    if (stat(*file_name, &buf) != 0) {
        std::cerr << "File does not exist!" << std::endl;
        exit(1);
    }
}

void load_events(const std::string& file_name, events_content_map_t& e_content, events_t_count_map_t& e_t_count) {
    std::ifstream file(file_name);
    size_t event_id = MIN_EVENT_ID;

    if (file.is_open()) {
        std::string description;
        std::string number_of_tickets;

        while (std::getline(file, description) && std::getline(file, number_of_tickets)) {
            if (event_id > MAX_EVENT_ID) {
                std::cerr << "Too many events!" << std::endl;
                exit(1);
            }

            unsigned long converted_number_of_tickets = strtoul(number_of_tickets.c_str(), nullptr, DECIMAL_BASE);

            if (converted_number_of_tickets > UINT16_MAX) {
                std::cerr << "Too many tickets!" << std::endl;
                exit(1);
            }

            Event next_event = Event(description.length(), description);
            e_content.insert(std::make_pair(event_id, next_event));
            e_t_count.insert(std::make_pair(event_id, (ticket_count_t)converted_number_of_tickets));

            event_id++;
        }

        file.close();
    } else {
        std::cerr << "File opening error!" << std::endl;
        exit(1);
    }
}

class Server {
public:
    events_content_map_t events_content_map;
    events_t_count_map_t events_t_count_map;
    reservation_map_t reservations_map;
    std::unordered_set<ticket_t> used_tickets;
    std::unordered_set<cookie_t> used_cookies;

    uint16_t port;
    unsigned long timeout;

    message_id_t* buffer;

    reservation_id_t next_reservation_id = MIN_RESERVATION_ID;

    Server(uint16_t input_port, unsigned long input_timeout, events_content_map_t ev_c, events_t_count_map_t ev_t_c) :
            port(input_port), timeout(input_timeout), events_content_map(std::move(ev_c)), events_t_count_map(std::move(ev_t_c)) {
        reservations_map = reservation_map_t();
        used_tickets = std::unordered_set<ticket_t>();
        used_cookies = std::unordered_set<cookie_t>();
        buffer = static_cast<message_id_t*>(calloc(BUFFER_SIZE_IN_BYTES, sizeof(char)));
    }

    int bind_socket() const {
        int socket_fd = socket(AF_INET, SOCK_DGRAM, 0); // creating IPv4 UDP socket
        // after socket() call; we should close(sock) on any execution path;

        auto server_address = sockaddr_in();
        server_address.sin_family = AF_INET; // IPv4
        server_address.sin_addr.s_addr = htonl(INADDR_ANY); // listening on all interfaces
        server_address.sin_port = htons(port);

        // bind the socket to a concrete address
        bind(socket_fd, (struct sockaddr *) &server_address,
             (socklen_t) sizeof(server_address));

        return socket_fd;
    }

    size_t read_message(int socket_fd, struct sockaddr_in *client_address, size_t max_length) const {
        auto address_length = (socklen_t) sizeof(*client_address);
        int flags = 0; // we do not request anything special
        errno = 0;
        ssize_t len = recvfrom(socket_fd, buffer, max_length, flags,
                               (struct sockaddr *) client_address, &address_length);
        return (size_t) len;
    }

    static void send_message(int socket_fd, const struct sockaddr_in *client_address, const char *message, size_t length) {
        auto address_length = (socklen_t) sizeof(*client_address);
        int flags = 0;
        sendto(socket_fd, message, length, flags,(struct sockaddr *) client_address, address_length);
    }

    [[noreturn]] void run() {
        int socket_fd = bind_socket();
        auto client_address = sockaddr_in();
        size_t read_length;

        while (true) {
            read_length = read_message(socket_fd, &client_address, BUFFER_SIZE_IN_BYTES);

            if (read_length == get_events_length || read_length == get_reservation_length || read_length == get_tickets_length) {
                check_reservations_timeout();
                if (respond(&read_length)) {
                    send_message(socket_fd, &client_address, (char*)buffer, read_length);
                }
            }
        }
    }

    void check_reservations_timeout() {
        auto to_delete = std::vector<reservation_id_t>();

        for (const auto& reservation : reservations_map) {
            auto r_id = reservation.first;
            auto r_content = reservation.second;

            if ((!r_content.tickets_acquired) && (r_content.expiration_time < get_seconds_since_epoch())) {
                events_t_count_map[r_content.event_id] += r_content.ticket_count;
                to_delete.push_back(r_id);
            }
        }

        for (auto r_id : to_delete) {
            reservations_map.erase(r_id);
        }
    }

    bool respond(size_t* length) {
        switch (*buffer) {
            case GET_EVENTS_ID: {
                return respond_events(length);
            }
            case GET_RESERVATION_ID: {
                return respond_reservation(length);
            }
            case GET_TICKETS_ID: {
                return respond_tickets(length);
            }
            default:
                return false;
        }
    }

    bool respond_events(size_t* length) {
        auto events_output = Events_output(events_content_map, events_t_count_map);
        events_output.write_raw_data_to_buffer(buffer, length);

        return true;
    }

    bool respond_reservation(size_t* length) {
        auto input_reservation = Get_reservation(buffer);
        bool found_event = false;
        bool message_too_long = sizeof(message_id_t) + sizeof(reservation_id_t) + sizeof(ticket_count_t) +
                input_reservation.ticket_count * sizeof(char) * TICKET_LENGTH_IN_BYTES > BUFFER_SIZE_IN_BYTES;



        if (events_content_map.size() > input_reservation.event_id) {
            found_event = true;
        }

        if (!found_event || message_too_long || input_reservation.ticket_count == 0 ||
            events_t_count_map.find(input_reservation.event_id)->second < input_reservation.ticket_count) {

            auto bad_request = Bad_request_output(input_reservation.event_id);
            bad_request.write_raw_data_to_buffer(buffer, length);

            return true;

        }

        events_t_count_map.find(input_reservation.event_id)->second -= input_reservation.ticket_count;
        expiration_time_t timeout_time = get_seconds_since_epoch();
        timeout_time += timeout;

        std::string cookie (COOKIE_LENGTH_IN_BYTES, 'x');
        do {
            for (int i = 0; i < COOKIE_LENGTH_IN_BYTES; ++i) {
                cookie[i] = random_cookie_char();
            }
        } while (used_cookies.find(cookie) != used_cookies.end());
        used_cookies.insert(cookie);
        auto reservation = Reservation(input_reservation.event_id, input_reservation.ticket_count,
                                       cookie, timeout_time);
        reservations_map.insert(std::make_pair(next_reservation_id, reservation));

        auto reservation_output = Reservation_output(next_reservation_id, input_reservation.event_id,
                                                     input_reservation.ticket_count, cookie, timeout_time);
        reservation_output.write_raw_data_to_buffer(buffer, length);
        next_reservation_id++;

        return true;
    }

    bool respond_tickets(size_t* length) {
        auto input_tickets = Get_tickets(buffer);

        auto reservation = reservations_map.find(input_tickets.reservation_id);

        if (reservation == reservations_map.end()) {
            auto bad_request = Bad_request_output(input_tickets.reservation_id);
            bad_request.write_raw_data_to_buffer(buffer, length);
            return true;
        }

        auto r_id = reservation->first;
        auto r_content = reservation->second;

        if (r_content.cookie != input_tickets.cookie) {
            auto bad_request = Bad_request_output(input_tickets.reservation_id);
            bad_request.write_raw_data_to_buffer(buffer, length);
            return true;
        }

        if (!r_content.tickets_acquired) {
            ticket_t new_ticket (TICKET_LENGTH_IN_BYTES, 'x');
            auto new_tickets = std::vector<ticket_t>();
            for (size_t i = 0; i < r_content.ticket_count; ++i) {
                do {
                    for (size_t j = 0; j < TICKET_LENGTH_IN_BYTES; ++j) {
                        new_ticket[j] = random_ticket_char();
                    }
                } while (used_tickets.find(new_ticket) != used_tickets.end());
                used_tickets.insert(new_ticket);
                new_tickets.push_back(new_ticket);
            }

            r_content.tickets_acquired = true;
            r_content.tickets = new_tickets;

            reservations_map.insert_or_assign(r_id, r_content);
        }

        auto tickets_output = Tickets_output(r_id, r_content.ticket_count, r_content.tickets);
        tickets_output.write_raw_data_to_buffer(buffer);
        *length = sizeof(message_id_t) + sizeof(reservation_id_t) + sizeof(ticket_count_t) +
                r_content.ticket_count * sizeof(char) * TICKET_LENGTH_IN_BYTES;

        return true;
    }
};

int main(int argc, char* argv[]) {
    srand( get_seconds_since_epoch());

    const char *file_name_char_ptr = nullptr;
    unsigned long port = DEFAULT_PORT;
    unsigned long timeout = DEFAULT_TIMEOUT;

    set_flags(argc, argv, &file_name_char_ptr, port, timeout);

    std::string file_name = (std::string) file_name_char_ptr;

    auto events_content = events_content_map_t();
    auto events_t_count = events_t_count_map_t();
    load_events(file_name, events_content, events_t_count);

    auto server = Server((uint16_t)port, timeout, events_content, events_t_count);

    server.run();
}