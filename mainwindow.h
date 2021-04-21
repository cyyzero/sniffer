#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <mutex>
#include <QMainWindow>
#include "sniffer.h"
#include "packetparser.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    using ResultPtr = std::shared_ptr<PacketParseResult>;
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

public slots:
    void inputFinished();
    void tableCellClicked(int row, int col);


private slots:
    void on_startButton_clicked();

    void on_pauseButton_clicked();

    void on_clearButton_clicked();

    void startSniffer();
    void stopSniffer();
    void clearTable();
    void fillInDevices();
    int tableAddItem(const QVector<QString>& item);
    int tableAddItem(const ResultPtr& r, int no);
    void tableAddItem(const ResultPtr& r);
    void hideTableRow(int row);
    void showTableRow(int row);
    void displayPacketLayers(const ResultPtr& p);
    void displayPacketBinary(const ResultPtr& p);
    void clearTreeWidget();
    void clearListWidget();
    void fillInTable();
private:
    Ui::MainWindow *ui_;
    Sniffer sniffer_;
    bool isRunning_;
    int deviceIndex_;
    std::mutex m_;
    std::vector<ResultPtr> results_;
    std::function<bool(const MainWindow::ResultPtr&)> filter_;
};
#endif // MAINWINDOW_H
