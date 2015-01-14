#include "net/quic/quic_connection.h"
#include "net/quic/quic_clock.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/crypto/quic_random.h"

#include "base/command_line.h"
#include "base/at_exit.h"
#include "base/logging.h"

#include <iostream>
#include <vector>

#define EXPECT_TRUE(x) { if (!(x)) printf("ERROR"); }

using namespace net;
using namespace std;

class TestConnectionHelper : public QuicConnectionHelperInterface {
  public:
    class TestAlarm : public QuicAlarm {
      public:
        explicit TestAlarm(QuicAlarm::Delegate* delegate)
          : QuicAlarm(delegate) {
          }

        void SetImpl() override {}
        void CancelImpl() override {}
        using QuicAlarm::Fire;
    };

    TestConnectionHelper(QuicClock* clock, QuicRandom* random_generator)
      : clock_(clock),
      random_generator_(random_generator) {
      }

    // QuicConnectionHelperInterface
    const QuicClock* GetClock() const override { return clock_; }

    QuicRandom* GetRandomGenerator() override { return random_generator_; }

    QuicAlarm* CreateAlarm(QuicAlarm::Delegate* delegate) override {
      return new TestAlarm(delegate);
    }

  private:
    QuicClock* clock_;
    QuicRandom* random_generator_;

    DISALLOW_COPY_AND_ASSIGN(TestConnectionHelper);
};


class TestPacketWriter : public QuicPacketWriter {
 public:
  TestPacketWriter(QuicClock *clock)
      : framer_(QuicSupportedVersions(), QuicTime::Zero(), true),
        last_packet_size_(0),
        write_blocked_(false),
        block_on_next_write_(false),
        is_write_blocked_data_buffered_(false),
        final_bytes_of_last_packet_(0),
        final_bytes_of_previous_packet_(0),
        use_tagging_decrypter_(false),
        packets_write_attempts_(0),
        clock_(clock) {
  }

  // QuicPacketWriter interface
  WriteResult WritePacket(const char* buffer,
                          size_t buf_len,
                          const IPAddressNumber& self_address,
                          const IPEndPoint& peer_address) override {
    QuicEncryptedPacket packet(buffer, buf_len);
    ++packets_write_attempts_;

    if (packet.length() >= sizeof(final_bytes_of_last_packet_)) {
      final_bytes_of_previous_packet_ = final_bytes_of_last_packet_;
      memcpy(&final_bytes_of_last_packet_, packet.data() + packet.length() - 4,
             sizeof(final_bytes_of_last_packet_));
    }

//    if (use_tagging_decrypter_) {
//      framer_.SetDecrypter(new TaggingDecrypter, ENCRYPTION_NONE);
//    }
    EXPECT_TRUE(framer_.ProcessPacket(packet));
    if (block_on_next_write_) {
      write_blocked_ = true;
      block_on_next_write_ = false;
    }
    if (IsWriteBlocked()) {
      return WriteResult(WRITE_STATUS_BLOCKED, -1);
    }
    last_packet_size_ = packet.length();

    return WriteResult(WRITE_STATUS_OK, last_packet_size_);
  }

  bool IsWriteBlockedDataBuffered() const override {
    return is_write_blocked_data_buffered_;
  }

  bool IsWriteBlocked() const override { return write_blocked_; }

  void SetWritable() override { write_blocked_ = false; }

  void BlockOnNextWrite() { block_on_next_write_ = true; }

  size_t last_packet_size() {
    return last_packet_size_;
  }

  void set_is_write_blocked_data_buffered(bool buffered) {
    is_write_blocked_data_buffered_ = buffered;
  }

  // final_bytes_of_last_packet_ returns the last four bytes of the previous
  // packet as a little-endian, uint32. This is intended to be used with a
  // TaggingEncrypter so that tests can determine which encrypter was used for
  // a given packet.
  uint32 final_bytes_of_last_packet() { return final_bytes_of_last_packet_; }

  // Returns the final bytes of the second to last packet.
  uint32 final_bytes_of_previous_packet() {
    return final_bytes_of_previous_packet_;
  }

  void use_tagging_decrypter() {
    use_tagging_decrypter_ = true;
  }

  uint32 packets_write_attempts() { return packets_write_attempts_; }

 private:
  QuicFramer framer_;
  size_t last_packet_size_;
  bool write_blocked_;
  bool block_on_next_write_;
  bool is_write_blocked_data_buffered_;
  uint32 final_bytes_of_last_packet_;
  uint32 final_bytes_of_previous_packet_;
  bool use_tagging_decrypter_;
  uint32 packets_write_attempts_;
  QuicClock *clock_;

  DISALLOW_COPY_AND_ASSIGN(TestPacketWriter);
};


class MockPacketWriterFactory : public QuicConnection::PacketWriterFactory {
 public:
  explicit MockPacketWriterFactory(QuicPacketWriter* writer) {
//    ON_CALL(*this, Create(_)).WillByDefault(Return(writer));
    writer_ = writer;
  }
  virtual ~MockPacketWriterFactory() override {}

  virtual QuicPacketWriter *Create(QuicConnection* connection) const override {
    return writer_;
  }

 private:
  QuicPacketWriter *writer_;
};


int main(int argc, char *argv[]) {
  base::CommandLine::Init(argc, argv);
  base::AtExitManager exit_manager;
  logging::SetMinLogLevel(-1);

  std::cout << "Hello world!" << std::endl;

  //TestConnectionHelper helper_ = new TestConnectionHelper(&clock_, &random_generator_);
  //TestPacketWriter writer_ = new TestPacketWriter(version(), &clock_);
  //NiceQuic<QuicPacketWriterFactory> factory_;

  //QuicConnection* conn = new QuicConnection(connection_id, IPEndPoint(), helper_.get(), factory_, true, true, true, version());

  //
  QuicConnectionId connection_id = 42;
  QuicClock clock_;
  QuicRandom* random_generator_ = QuicRandom::GetInstance();

  TestConnectionHelper *helper = new TestConnectionHelper(&clock_, random_generator_);
  TestPacketWriter *writer = new TestPacketWriter(&clock_);
  QuicVersionVector supported_versions;
  for (size_t i = 0; i < arraysize(kSupportedQuicVersions); ++i) {
    supported_versions.push_back(kSupportedQuicVersions[i]);
  }
  MockPacketWriterFactory factory(writer);

  QuicConnection* conn = new QuicConnection(connection_id, IPEndPoint(), helper, factory, true, true, true, supported_versions); 

  QuicPublicResetPacket header;
  QuicFramer framer_(QuicSupportedVersions(), QuicTime::Zero(), true);
  header.public_header.connection_id = 42;
  header.public_header.reset_flag = true;
  header.public_header.version_flag = false;
  header.rejected_sequence_number = 10101;
  scoped_ptr<QuicEncryptedPacket> packet(
      framer_.BuildPublicResetPacket(header));
  conn->ProcessUdpPacket(IPEndPoint(), IPEndPoint(), *packet);

  std::cout << conn << std::endl;
  return 0;
}
