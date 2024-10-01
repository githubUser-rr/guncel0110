#ifndef PCAPPPACKET_H
#define PCAPPPACKET_H

#include "backProcessCls.h"

#include <SipLayer.h>
#include <PcapFileDevice.h>
#include <Packet.h>
#include <EthLayer.h>
#include <IPv4Layer.h>
#include "TcpLayer.h"
#include "UdpLayer.h"
#include <PcapPlusPlusVersion.h>
#include <SdpLayer.h>



#include <QString>
#include <QDebug>
#include <QVector>



class pcapPpacket
{
public:
    pcapPpacket(const QString& path);
    void processPcap();
    ~pcapPpacket();

private:
    void parseSipPacket();
    QString sipMethodToQString(pcpp::SipRequestLayer::SipMethod method);
    pcpp::IFileReaderDevice* reader;
    QVector<pcpp::RawPacket> packets;

    QThread* th;
    QString pcapPath;
    int packetCount;

    backProcessCls* bCls;

    QString fileName;
    QString directory;

};

#endif // PCAPPPACKET_H
