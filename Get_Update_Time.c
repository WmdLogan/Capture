

#include <sys/stat.h>
#include <stdio.h>

int main( void )
{
    struct stat buf;
    int result;
    //获得文件状态信息
    result =stat( "/home/logan/CLionProjects/Capture/mytest.conf", &buf );
    //显示文件状态信息
    if( result != 0 )
        perror( "显示文件状态信息出错" );//并提示出错的原因，如No such file or directory（无此文件或索引）

    else
    {
        printf("文件大小: %ld\n", buf.st_size);
        printf("文件创建时间: %ld\n", buf.st_ctime);
    }
    return 0;
}
