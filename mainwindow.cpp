#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "utility.h"
#include <QMessageBox>
#include <thread>
#include <QLineEdit>
#include <QTextBrowser>
#include <QtDebug>


namespace
{
bool defaultFilter(const MainWindow::ResultPtr&)
{
    return true;
}

#define genFilterDefination(lower, upper) \
    bool lower##Filter(const MainWindow::ResultPtr& ptr) \
    { \
        return ptr->is##upper; \
    }

genFilterDefination(http, HTTP)
genFilterDefination(tls, TLS)
genFilterDefination(tcp, TCP)
genFilterDefination(udp, UDP)
genFilterDefination(arp, ARP)
genFilterDefination(ipv4, IPv4)
genFilterDefination(icmp, ICMP)

void dfsDeleteTreeItem(QTreeWidgetItem* node)
{
    if (!node)
        return;
    int cnt = node->childCount();
    for (int i = 0; i < cnt; ++i)
    {
        dfsDeleteTreeItem(node->takeChild(i));
    }
    delete node;
}

} // namespace

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui_(new Ui::MainWindow)
    , isRunning_(false)
    , deviceIndex_(-1)
    , filter_(defaultFilter)
{
    ui_->setupUi(this);
    connect(ui_->pushButton, &QPushButton::clicked, ui_->lineEdit, &QLineEdit::returnPressed);
    connect(ui_->lineEdit, &QLineEdit::returnPressed, this, &MainWindow::inputFinished);
    connect(ui_->tableWidget, &QTableWidget::cellClicked, this, &MainWindow::tableCellClicked);
//    connect(ui_->)

//    std::thread t([this] () {
//        for (int i = 0; i < 100; ++i)
//        {
//            using namespace std::chrono_literals;
//            auto idx = tableAddItem(QVector<QString>{QString::number(i), "1.1.1.1"});
//            qDebug() << idx << " " << ui_->tableWidget->rowCount();
//            std::this_thread::sleep_for(1000ms);
//            hideTableRow(idx);
//        }
//    });
//    t.detach();

    ui_->tableWidget->verticalHeader()->setVisible(false);
    fillInDevices();

    sniffer_.setParsedCallback([this] (const ResultPtr& ptr) {
        this->tableAddItem(ptr);
    });
}

MainWindow::~MainWindow()
{
    delete ui_;
}

void MainWindow::inputFinished()
{

    std::lock_guard<std::mutex> lk(m_);
    qDebug() << "filter policy: " << ui_->lineEdit->text();
    auto s = ui_->lineEdit->text().toLower();
    bool illegal = false;

#define setFilter(protocol) \
    if (s == #protocol) \
    { \
        filter_ = protocol##Filter;\
        illegal = true; \
        qDebug () << #protocol << "Filter chosen"; \
    }

    setFilter(http);
    setFilter(tls);
    setFilter(tcp);
    setFilter(udp);
    setFilter(icmp);
    setFilter(ipv4);
    setFilter(arp);

    if (!illegal)
    {
        qDebug() << "default filter chosen";
        filter_ = defaultFilter;
    }

    clearTable();
    fillInTable();
}

void MainWindow::tableCellClicked(int row, int)
{
    int n = ui_->tableWidget->item(row, 0)->text().toInt();
    if (n >= (int)results_.size())
    {
        return;
    }
    clearTreeWidget();
    clearListWidget();
    const auto& ptr = results_[n];
    qDebug() << "tree row " << row << " clicked";
    displayPacketLayers(ptr);
    displayPacketBinary(ptr);
}

int MainWindow::tableAddItem(const QVector<QString>& items)
{
    auto table = ui_->tableWidget;
    int rowIdx = table->rowCount();
    table->insertRow(rowIdx);
    // hideTableRow(rowIdx);
    for (int i = 0; i < items.size(); ++i)
    {
        auto item =  new QTableWidgetItem(items[i]);
        item->setTextAlignment(Qt::AlignHCenter | Qt::AlignVCenter);
        table->setItem(rowIdx, i, item);
    }

    return rowIdx;
}

int MainWindow::tableAddItem(const ResultPtr&r, int num)
{
    QString No, src, dest, protocol, length;
    No = QString::number(num);
    if (r->isIPv4)
    {
        src = QString(r->ipv4Header->getSourceIPStr().c_str());
        dest = QString(r->ipv4Header->getDestinationIPStr().c_str());
    }
    else
    {
        src = QString(r->ethernetHeader->getSrcMAC().c_str());
        dest = QString(r->ethernetHeader->getDestMAC().c_str());
    }


    if (r->isHTTP)
    {
        protocol = "HTTP";
    }
    else if (r->isTLS)
    {
        protocol= "TLS";
    }
    else if (r->isTCP)
    {
        protocol = "TCP";
    }
    else if (r->isUDP)
    {
        protocol = "UDP";
    }
    else if (r->isICMP)
    {
        protocol = "ICMP";
    }
    else if (r->isIPv4)
    {
        protocol = "IPv4";
    }
    else if (r->isARP)
    {
        protocol = "ARP";
    }
    else
    {
        protocol = "Ethernet II";
    }

    length  = QString::number(r->len_);
    return tableAddItem(QVector<QString>{No, src, dest, protocol, length});
}

void MainWindow::tableAddItem(const MainWindow::ResultPtr &r)
{
    if (r->isIPv6)
        return;
    int num;
    std::lock_guard<std::mutex> lk(m_);
    num = results_.size();
    results_.push_back(r);
    if (!(filter_ && filter_(r)))
    {
        return;
    }
    tableAddItem(r, num);

//    if (filter_ && filter_(r))
//    {
//         showTableRow(rowIdx);
//    }

}

void MainWindow::hideTableRow(int row)
{
    ui_->tableWidget->removeRow(row);
    //ui_->tableWidget->hideRow(row);
    // ui_->tableWidget->setRowHidden(row, true);
}

void MainWindow::showTableRow(int row)
{
    ui_->tableWidget->showRow(row);
    // ui_->tableWidget->setRowHidden(row, false);
}

void MainWindow::startSniffer()
{
    int deviceIndex = ui_->comboBox->currentIndex();
    qDebug() << "select device No." << deviceIndex;
    if (isRunning_ && deviceIndex == deviceIndex_)
    {
        return;
    }
    if (!isRunning_ || (isRunning_ && deviceIndex != deviceIndex_))
    {
        if (isRunning_)
            sniffer_.stop();
        if (deviceIndex != deviceIndex_)
        {
            results_.clear();
            clearTable();
        }
//        if (!isRunning_ && deviceIndex != deviceIndex)
//            clearTable();
        isRunning_ = true;
        deviceIndex_ = deviceIndex;
        sniffer_.selectDevice(deviceIndex);
        sniffer_.start();
    }
}

void MainWindow::stopSniffer()
{
    if (isRunning_)
    {
        sniffer_.stop();
    }
    isRunning_ = false;
}

void MainWindow::clearTable()
{
    int len;
    len = ui_->tableWidget->rowCount();
    // qDebug() << len << "rows";
     for (int i = 0; i < len; ++i)
     {
         int colCnt = ui_->tableWidget->columnCount();
         for (int j = 0; j < colCnt; ++j)
         {
             auto item = ui_->tableWidget->takeItem(0, j);
             delete item;
         }
         ui_->tableWidget->removeRow(0);
     }
}

void MainWindow::displayPacketLayers(const ResultPtr &p)
{
    auto tree = ui_->treeWidget;
    QString str;
    QTreeWidgetItem* parent, *child;

#define treeAddTopLevelItem(s) \
    parent = new QTreeWidgetItem(QStringList{s});\
    tree->addTopLevelItem(parent)

#define parentAddChild(hdr, s, func) \
    str = s; \
    str.append(hdr->func().c_str()); \
    child = new QTreeWidgetItem(QStringList{str}); \
    parent->addChild(child);


    // Ethernet II
#define EthernetParentAddChild(s, func) parentAddChild(p->ethernetHeader, s, func)

    treeAddTopLevelItem("Ethernet II");
    EthernetParentAddChild("Destination: ",getDestMAC);
    EthernetParentAddChild("Source: ", getSrcMAC);
    EthernetParentAddChild("Type: ", getTypeStr);

    if (p->isARP)
    {
        qDebug() << "arp: " << (void*)p->start_ << " " << p->len_ << " " << (void*)p->arpHeader;
        // ARP
        treeAddTopLevelItem("Address Resolution Protocol");
#define ARPParentAddChild(s, func) parentAddChild(p->arpHeader, s, func)
        ARPParentAddChild("Hardware type: ", getHardWareType);
        ARPParentAddChild("Protocol type: ", getProtocolType);
        ARPParentAddChild("Hardware size: ", getHardWareSize);
        ARPParentAddChild("Protocol size:", getProtocolSize);
        ARPParentAddChild("Opcode: ", getOpcode);
        ARPParentAddChild("Sender MAC address: ", getSenderMAC);
        ARPParentAddChild("Sender IP address: ", getSenderIP);
        ARPParentAddChild("Target MAC address: ", getTargetMAC);
        ARPParentAddChild("Target IP address: ", getTargetIP);
    }
    else if (p->isIPv4)
    {
        // IPv4
        treeAddTopLevelItem("Internet Protocol Version 4");

#define IPv4ParentAddChild(s, func) parentAddChild(p->ipv4Header, s, func)

        IPv4ParentAddChild("Version: ", getVersionStr);
        IPv4ParentAddChild("Header length: ", getHeaderLengthStr);
        // Differentiated Services
        child = new QTreeWidgetItem(QStringList{"Differentiated services"});
        parent->addChild(child);
        auto node3 = new QTreeWidgetItem(QStringList{QString("DSCP: ").
                append(p->ipv4Header->getDSCPStr().c_str())});
        child->addChild(node3);
        node3 = new QTreeWidgetItem(QStringList{QString("ECN: ").
                append(p->ipv4Header->getECNStr().c_str())});
        child->addChild(node3);

        IPv4ParentAddChild("Total length: ", getTotalLengthStr);
        IPv4ParentAddChild("Identification: ", getIdentificationStr);
        IPv4ParentAddChild("Flags: ", getFlagsStr);
        IPv4ParentAddChild("Fragmeng Offset: ", getOffsetStr);
        IPv4ParentAddChild("Time to live: ", getTTLStr);
        IPv4ParentAddChild("Protocol: ", getProtocol);
        IPv4ParentAddChild("Header checksum: ", getChecksumStr);
        IPv4ParentAddChild("Source address: ", getSourceIPStr);
        IPv4ParentAddChild("Destination address: ", getDestinationIPStr);
    }
    if (p->isICMP)
    {
        // ICMP
        treeAddTopLevelItem("Internet Control Message Protocol");

#define ICMPParentAddChild(s, func) parentAddChild(p->icmpHeader, s, func)

        ICMPParentAddChild("Type: ", getTypeStr);
        ICMPParentAddChild("Code: ", getCodeStr);
        ICMPParentAddChild("Checksum: ", getChecksum);
        if (p->icmpHeader->hasIdAndSeq())
        {
            ICMPParentAddChild("Identifier: ", getIdentifier);
            ICMPParentAddChild("Sequence number: ", getSequenceNumber);
        }
        else
        {
            ICMPParentAddChild("Rest: ", getRest);
        }

    }
    if (p->isUDP)
    {
        treeAddTopLevelItem("User Datagram Protocol");
#define UDPParentAddChild(s, func) parentAddChild(p->udpHeader, s, func)
        UDPParentAddChild("Source port: ", getSourcePortStr);
        UDPParentAddChild("Destination port: ", getSourcePortStr);
        UDPParentAddChild("Length: ", getLengthStr);
        UDPParentAddChild("Checksum: ", getChecksumStr);
    }
    else if (p->isTCP)
    {
        treeAddTopLevelItem("Transmission Control Protocol");
#define TCPParentAddChild(s, func) parentAddChild(p->tcpHeader, s, func)
        TCPParentAddChild("Source port: ", getSourcePortStr);
        TCPParentAddChild("Destination port: ", getDestPortStr);
        TCPParentAddChild("Sequence number: ", getSeqNumStr);
        TCPParentAddChild("Acknowledge number: ", getAckNumStr);
        TCPParentAddChild("Header length: ", getHeaderLengthStr);
        TCPParentAddChild("Flags: ", getFalgs);
        TCPParentAddChild("Window: ", getWindowSizeStr);
        TCPParentAddChild("Checksum: ", getChecksumStr);
        TCPParentAddChild("Urgent number: ", getUrgentPointerStr);
        if (p->tcpHeader->hasOptions())
        {
            TCPParentAddChild("Options: ", getOptionsStr);
        }
    }
    if (p->isHTTP)
    {
        treeAddTopLevelItem("Hypertext Transfer Protocol");
#define HTTPParentAddChild(str) \
    child = new QTreeWidgetItem(QStringList{str}); \
    parent->addChild(child);

        auto strs = p->httpHeader->getHeaderLines();
        HTTPParentAddChild(strs[0].c_str());
        HTTPParentAddChild("headers:");
        for (int i = 1; i < (int)strs.size(); ++i)
        {
            if (strs[i].empty())
                continue;
            auto node3 = new QTreeWidgetItem(QStringList{strs[i].c_str()});
            child->addChild(node3);
        }
        auto body = p->httpHeader->getBody();
        if (!body.empty())
        {
            HTTPParentAddChild("body: ");
            child->addChild(new QTreeWidgetItem(QStringList{body.c_str()}));
        }
    }
    if (p->isTLS)
    {
        treeAddTopLevelItem("Transport Layer Security");
#define TLSParentAddChild(s, func) parentAddChild(p->tlsHeader, s, func)
        TLSParentAddChild("Content type: ", getTypeStr);
        TLSParentAddChild("Version: ", getVersionStr);
        TLSParentAddChild("Length: ", getLengthStr);
        int len = p->getPayloadLength() - sizeof(TLSHeader);
        bool tooLong = false;
        if (len >= 30)
        {
            tooLong = true;
            len = 30;
        }
        std::string hexStr = to_hex_string(p->currPtr_, len);
        if (tooLong)
            hexStr.append("...");
        child = new QTreeWidgetItem(QStringList{"Content:"});
        parent->addChild(child);
        child->addChild(new QTreeWidgetItem(QStringList{hexStr.c_str()}));
    }

    int restLength = p->getPayloadLength();
    qDebug() << "There're " << restLength << " bytes left.";
    if (!(p->isHTTP || p->isTLS || p->isARP) && restLength > 0)
    {
        treeAddTopLevelItem("Data: ");
        bool tooLong = false;
        if (restLength >= 30)
        {
            tooLong = true;
            restLength = 30;
        }
        std::string hexStr = to_hex_string(p->currPtr_, restLength);
        if (tooLong)
            hexStr.append("...");
        parent->addChild(new QTreeWidgetItem(QStringList{hexStr.c_str()}));
    }
}

void MainWindow::displayPacketBinary(const ResultPtr& p)
{
    qDebug() << "arp 2 : "<< p->start_ << " " << p->len_;
    auto list = ui_->listWidget;
    const char* start = (const char*)p->start_;
    size_t len = p->len_;
    size_t i = 0;
    QString buf1, buf2;
    for (; i < len; ++i)
    {
        if (i % 16 == 0 && !buf1.isEmpty())
        {
            list->addItem(buf1 + "     " + buf2);
            buf1.clear();
            buf2.clear();
        }
        char buf[8], ch;
        snprintf(buf, 8, "%02x ", (int)start[i] & 0xff);
        qDebug() << i << " " << buf ;
        buf1.append(buf);
        ch = start[i];
        if (!isgraph(ch))
        {
            ch = '*';
        }
        buf2.push_back(ch);
    }
    while (buf2.size() != 16)
    {
        buf1.push_back("   ");
        buf2.push_back(' ');
    }
    list->addItem(buf1 + "     " + buf2);

}

void MainWindow::clearTreeWidget()
{
    auto tree = ui_->treeWidget;
    auto topLevelCnt = tree->topLevelItemCount();
    for (int i = 0; i < topLevelCnt; ++i)
    {
        auto topItem = tree->takeTopLevelItem(i);
        dfsDeleteTreeItem(topItem);
    }
    tree->clear();
}

void MainWindow::clearListWidget()
{
    auto list = ui_->listWidget;
    int count = list->count();
    for (int i = 0; i < count; ++i)
    {
        auto p = list->takeItem(i);
        delete p;
    }
    list->clear();
}

void MainWindow::on_startButton_clicked()
{
    startSniffer();
}

void MainWindow::on_pauseButton_clicked()
{
    stopSniffer();
}

void MainWindow::on_clearButton_clicked()
{
    std::lock_guard<std::mutex> lk(m_);
    clearTable();
}

void MainWindow::fillInDevices()
{
    auto names = sniffer_.getDeviceNames();
    qDebug() << names.size();
    for (auto name: names)
    {
        ui_->comboBox->addItem(name);
    }
}

void MainWindow::fillInTable()
{
    for (int i = 0; i < (int)results_.size(); ++i)
    {
        if (filter_ && filter_(results_[i]))
            tableAddItem(results_[i], i);
    }
}


