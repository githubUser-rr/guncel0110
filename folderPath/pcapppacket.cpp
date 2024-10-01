#include "pcapppacket.h"
#include "pPlusnewstructs.h"
#include "MoveWorker.h"

#include <filesystem>
#include <QFile>
#include <QFileInfo>
#include <SipLayer.h>




pcapPpacket::pcapPpacket(const QString& path) : pcapPath(path),packetCount(0),packets(){

    while(true){
        QFileInfo fInfo(pcapPath);
        QDateTime modifyDate = fInfo.lastModified();
        QDateTime currTime = QDateTime::currentDateTime();
        qint64 subSeconds = modifyDate.secsTo(currTime);


        if(subSeconds >= 4){
            qDebug() << "Simdiki zaman ile modify date farkı : " << subSeconds ;
            this->fileName = fInfo.fileName();
            this->directory = fInfo.path();
            break;
        }
        qDebug() << "Dosya yazma islemi devam ediyor , modify date  : " << subSeconds ;
        QThread::msleep(500);
    }

    reader = pcpp::IFileReaderDevice::getReader(pcapPath.toStdString());

    if(!reader->open()){
        qDebug() << "Pcap reader hatasıı :" << pcapPath;
        qFatal("Pcap reader açılamadı. Program durduruluyor.");
    }

    this->bCls = new backProcessCls(fileName);
    th = new QThread;
    this->bCls->moveToThread(th);

    QObject::connect(th,&QThread::started,bCls,&backProcessCls::controlMap);
    QObject::connect(bCls,&backProcessCls::mapFinished,th,&QThread::quit);
    QObject::connect(bCls,&backProcessCls::mapFinished,bCls,&backProcessCls::deleteLater);
    QObject::connect(th,&QThread::finished,th,&QThread::deleteLater);

    th->start();

}

void pcapPpacket::processPcap(){
    /*if(!reader || !reader->isOpened()){
        qDebug() << "Process reader hatası : " << pcapPath;
        return;
    }*/

    pcpp::RawPacket rawPacket;

    while(reader->getNextPacket(rawPacket)){
        packetCount++;
        packets.push_back(rawPacket);
        pPlusstrPacketInfo pInfo;
        pcpp::Packet parsed(&rawPacket);

        //qDebug() << "Zaman :" << rawPacket.getPacketTimeStamp().tv_sec << "saniye ve " << rawPacket.getPacketTimeStamp().tv_nsec << "ms";
        pInfo.timestamp  = QString("%1.%2").arg(rawPacket.getPacketTimeStamp().tv_sec).arg(rawPacket.getPacketTimeStamp().tv_nsec, 9, 10, QChar('0'));
        pInfo.packetLen = rawPacket.getRawDataLen();
        //qDebug() << "Len : " << rawPacket.getRawDataLen();
        //if(parsed.isPacketOfType(pcpp::Ethernet))
        pcpp::EthLayer* ethernetLayer = parsed.getLayerOfType<pcpp::EthLayer>();
        if(ethernetLayer != nullptr){
            pInfo.destMac = QString::fromStdString(ethernetLayer->getDestMac().toString());
            pInfo.sourceMac = QString::fromStdString(ethernetLayer->getSourceMac().toString());

        }

        if(parsed.isPacketOfType(pcpp::IPv4)){

            pcpp::IPv4Layer* ipLayer = parsed.getLayerOfType<pcpp::IPv4Layer>();
            if(ipLayer != nullptr){
                pInfo.sourceIP = QString::fromStdString(ipLayer->getSrcIPAddress().toString());
                pInfo.destIP = QString::fromStdString(ipLayer->getDstIPAddress().toString());
            }

            if(parsed.isPacketOfType(pcpp::TCP)){
                pcpp::TcpLayer* tcpLayer = parsed.getLayerOfType<pcpp::TcpLayer>();
                pInfo.protocol = "TCP";
                if(tcpLayer != nullptr){
                    pcpp::tcphdr* tcpHeader = (pcpp::tcphdr*)tcpLayer->getTcpHeader();
                    pInfo.ackFlag = tcpHeader->ackFlag;
                    pInfo.finFlag = tcpHeader->finFlag;

                    pInfo.sourcePort = tcpLayer->getSrcPort();
                    pInfo.destPort = tcpLayer->getDstPort();
                }
            }else if(parsed.isPacketOfType(pcpp::UDP)){
                pcpp::UdpLayer* udpLayer = parsed.getLayerOfType<pcpp::UdpLayer>();
                pInfo.protocol = "UDP";
                if(udpLayer != nullptr){
                    pInfo.sourcePort = udpLayer->getSrcPort();
                    pInfo.destPort = udpLayer->getDstPort();
                }
            }

        }

        if(parsed.isPacketOfType(pcpp::SIP)){
            QString message = "";
            QString cId = "";
            QString ip = "";
            QString seqNumber = "";
            uint16_t audioPort = 0;
            uint16_t videoPort = 0;
            int dir = -1;

            pcpp::SipLayer* sLayer = parsed.getLayerOfType<pcpp::SipLayer>();
            pcpp::HeaderField* callId = sLayer->getFieldByName("Call-ID");
            cId = QString::fromStdString(callId->getFieldValue());
            pcpp::HeaderField* cseqFiedl = sLayer->getFieldByName("CSeq");
            seqNumber = QString::fromStdString(cseqFiedl->getFieldValue());
            //qDebug() <<  "Seq number : " <<seqNumber << " " << packetCount;
            sLayer->parseNextLayer();
            pcpp::SdpLayer* sdpLayer = parsed.getLayerOfType<pcpp::SdpLayer>();
            if(sdpLayer != nullptr){

                audioPort = sdpLayer->getMediaPort("audio");
                videoPort = sdpLayer->getMediaPort("video");
                pcpp::HeaderField* c = sdpLayer->getFieldByName("c");
                ip = QString::fromStdString(c->getFieldValue());
                //qDebug() << "Audioport : " <<audioPort << "Video port : " << videoPort <<" ip " << connection;
            }

            if(parsed.isPacketOfType(pcpp::SIPRequest)){
                dir = 0;
                pcpp::SipRequestLayer* requestLayer = parsed.getLayerOfType<pcpp::SipRequestLayer>();
                if(requestLayer != nullptr){
                    pcpp::SipRequestFirstLine *firstLine = requestLayer->getFirstLine();
                    pcpp::SipRequestLayer::SipMethod m = firstLine->getMethod(); // bunu qstring dönüştür
                    message = this->sipMethodToQString(m);
                    //requestLayer->parseNextLayer();
                }
            }else if(parsed.isPacketOfType(pcpp::SIPResponse)){
                pcpp::SipResponseLayer* responseLayer = parsed.getLayerOfType<pcpp::SipResponseLayer>();
                if(responseLayer != nullptr){
                    pcpp::SipResponseFirstLine *firstLine = responseLayer->getFirstLine();
                    message = QString::number(firstLine->getStatusCode()) + " " + QString::fromStdString(firstLine->getStatusCodeString());
                    //qDebug() << message << packetCount;
                }

            }

            bCls->updateSipMap(message,cId,seqNumber,ip,audioPort,videoPort,dir);
            /*qDebug() << "Numara " << packetCount;
            qDebug() << "Message:" << message;
            qDebug() << "cId:" << cId;
            qDebug() << "IP:" << ip;
            qDebug() << "Audio Port:" << audioPort;
            qDebug() << "Media Port:" << videoPort;*/
        }


        /*if(parsed.isPacketOfType(pcpp::SIPRequest)){//gönderici tarafı
            //qDebug() << "Gönderici";
            pcpp::SipLayer* sLayer = parsed.getLayerOfType<pcpp::SipLayer>();
            pcpp::HeaderField* callId = sLayer->getFieldByName("Call-ID");
            QString cId = QString::fromStdString(callId->getFieldValue());
            pcpp::SipRequestLayer* requestLayer = parsed.getLayerOfType<pcpp::SipRequestLayer>();
            if(requestLayer != nullptr){
                pcpp::SipRequestFirstLine *firstLine = requestLayer->getFirstLine();
                pcpp::SipRequestLayer::SipMethod m = firstLine->getMethod(); // bunu qstring dönüştür
                QString method = this->sipMethodToQString(m);
                requestLayer->parseNextLayer();
                pcpp::SdpLayer* sdpLayer = parsed.getLayerOfType<pcpp::SdpLayer>();
                if(sdpLayer != nullptr){
                    uint16_t audioPort = sdpLayer->getvideoPort("audio");
                    uint16_t videoPort = sdpLayer->getvideoPort("video");
                    pcpp::HeaderField* c = sdpLayer->getFieldByName("c");
                    QString connection = QString::fromStdString(c->getFieldValue());

                    //qDebug() << "Audioport : " <<audioPort << "Video port : " << videoPort <<" ip " << connection;

                }
            }

        }else if (parsed.isPacketOfType(pcpp::SIPResponse)){
            pcpp::SipLayer* sLayer = parsed.getLayerOfType<pcpp::SipLayer>();
            pcpp::HeaderField* callId = sLayer->getFieldByName("Call-ID");
            QString cId = QString::fromStdString(callId->getFieldValue());
            pcpp::SipResponseLayer* responseLayer = parsed.getLayerOfType<pcpp::SipResponseLayer>();
            if(responseLayer != nullptr){
                pcpp::SipResponseFirstLine *firstLine = responseLayer->getFirstLine();
                QString message = QString::number(firstLine->getStatusCode()) + " " + QString::fromStdString(firstLine->getStatusCodeString());
                qDebug() << message << packetCount;
                responseLayer->parseNextLayer();
                pcpp::SdpLayer* sdpLayer = parsed.getLayerOfType<pcpp::SdpLayer>();
                if(sdpLayer != nullptr){
                    uint16_t audioPort = sdpLayer->getvideoPort("audio");
                    uint16_t videoPort = sdpLayer->getvideoPort("video");
                    pcpp::HeaderField* c = sdpLayer->getFieldByName("c");
                    QString connection = QString::fromStdString(c->getFieldValue());

                    qDebug() << "Audioport : " <<audioPort << "Video port : " << videoPort <<" ip " << connection;
                }

            }
        }*/

        bCls->addRawPacket(rawPacket,pInfo);

    }
    bCls->setIsLastPacket(true);
    qDebug() << "Total paket sayısı : " << packetCount;
    qDebug() << "Size : " << packets.size();


}

pcapPpacket::~pcapPpacket(){

    /*MoveWorker* mw =new MoveWorker(pcapPath);
    QThread* wThread = new QThread;
    mw->moveToThread(wThread);

    QObject::connect(wThread,&QThread::started,mw,&MoveWorker::moveFile);
    QObject::connect(mw,&MoveWorker::moveFinished,wThread,&QThread::quit);
    QObject::connect(mw,&MoveWorker::moveFinished,mw,&MoveWorker::deleteLater);
    QObject::connect(mw,&MoveWorker::failedMove,mw,&MoveWorker::deleteLater);
    QObject::connect(wThread,&QThread::finished,wThread,&QThread::deleteLater);
    wThread->start();
    wThread->wait();*/

    while(th != nullptr){
        qDebug() << "İslem devam ediyor.";
        th->wait();
    }
    qDebug() << "İslem bitti !! ";
    reader->close();
    if(reader != nullptr){
        delete reader;
        reader = nullptr;
    }


    qDebug() << "ppPacket dest";

}

QString pcapPpacket::sipMethodToQString(pcpp::SipRequestLayer::SipMethod method){
    switch (method) {
    case pcpp::SipRequestLayer::SipINVITE:
        return QString("INVITE");
    case pcpp::SipRequestLayer::SipACK:
        return QString("ACK");
    case pcpp::SipRequestLayer::SipBYE:
        return QString("BYE");
    case pcpp::SipRequestLayer::SipCANCEL:
        return QString("CANCEL");
    case pcpp::SipRequestLayer::SipREGISTER:
        return QString("REGISTER");
    case pcpp::SipRequestLayer::SipPRACK:
        return QString("PRACK");
    case pcpp::SipRequestLayer::SipOPTIONS:
        return QString("OPTIONS");
    case pcpp::SipRequestLayer::SipSUBSCRIBE:
        return QString("SUBSCRIBE");
    case pcpp::SipRequestLayer::SipNOTIFY:
        return QString("NOTIFY");
    case pcpp::SipRequestLayer::SipPUBLISH:
        return QString("PUBLISH");
    case pcpp::SipRequestLayer::SipINFO:
        return QString("INFO");
    case pcpp::SipRequestLayer::SipREFER:
        return QString("REFER");
    case pcpp::SipRequestLayer::SipMESSAGE:
        return QString("MESSAGE");
    case pcpp::SipRequestLayer::SipUPDATE:
        return QString("UPDATE");
    default:
        return QString("Unknown SIP method");
    }
}
