#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QMessageBox>
#include <QLineEdit>
#include <QTextBrowser>
#include <QtDebug>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui_(new Ui::MainWindow)
    , isRunning_(false)
    , deviceIndex_(-1)
{
    ui_->setupUi(this);
    connect(ui_->pushButton, &QPushButton::clicked, ui_->lineEdit, &QLineEdit::returnPressed);
    connect(ui_->lineEdit, &QLineEdit::returnPressed, this, &MainWindow::inputFinished);
    ui_->tableWidget->verticalHeader()->setVisible(false);
    fillInDevices();
    tableAddItem(QVector<QString>{"1", "1.1.1.1"});
}

MainWindow::~MainWindow()
{
    delete ui_;
}

void MainWindow::inputFinished()
{
    qDebug() << ui_->lineEdit->text();
}

void MainWindow::tableAddItem(const QVector<QString>& items)
{
    auto table = ui_->tableWidget;
    int rowIdx = table->rowCount();
    table->setRowCount(rowIdx+1);
    for (int i = 0; i < items.size(); ++i)
    {
        auto item =  new QTableWidgetItem(items[i]);
        item->setTextAlignment(Qt::AlignHCenter | Qt::AlignVCenter);
        table->setItem(rowIdx, i, item);
    }

}


void MainWindow::on_startButton_clicked()
{
    int deviceIndex = ui_->comboBox->currentIndex();
    qDebug() << "select device No." << deviceIndex;
    if (isRunning_ && deviceIndex == deviceIndex_)
    {
        return;
    }
    if (!isRunning_ || (isRunning_ && deviceIndex != deviceIndex_))
    {
        isRunning_ = true;
        deviceIndex_ = deviceIndex;
        sniffer_.stop();
        sniffer_.selectDevice(deviceIndex);
        sniffer_.start();
    }

}

void MainWindow::on_pauseButton_clicked()
{
    if (isRunning_)
    {
        sniffer_.stop();
    }
    isRunning_ = false;
}

void MainWindow::on_clearButton_clicked()
{
    // TODO: remove all rows
    // ui_->
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

