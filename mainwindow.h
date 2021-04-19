#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "sniffer.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

public slots:
    void inputFinished();


private slots:
    void on_startButton_clicked();

    void on_pauseButton_clicked();

    void on_clearButton_clicked();

private:
    void fillInDevices();
    void tableAddItem(const QVector<QString>& item);
    Ui::MainWindow *ui_;
    Sniffer sniffer_;
    bool isRunning_;
    int deviceIndex_;
};
#endif // MAINWINDOW_H
