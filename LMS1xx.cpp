/*
 * LMS1xx.cpp
 *
 *  Created on: 09-08-2010
 *  Author: Konrad Banachowicz
 ***************************************************************************
 *   This library is free software; you can redistribute it and/or         *
 *   modify it under the terms of the GNU Lesser General Public            *
 *   License as published by the Free Software Foundation; either          *
 *   version 2.1 of the License, or (at your option) any later version.    *
 *                                                                         *
 *   This library is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU     *
 *   Lesser General Public License for more details.                       *
 *                                                                         *
 *   You should have received a copy of the GNU Lesser General Public      *
 *   License along with this library; if not, write to the Free Software   *
 *   Foundation, Inc., 59 Temple Place,                                    *
 *   Suite 330, Boston, MA  02111-1307  USA                                *
 *                                                                         *
 ***************************************************************************/

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <time.h>
#include <cmath>

#include "LMS1xx.h"

LMS1xx::LMS1xx() :
	connected(false) {
	debug = false;
	q_len = 0;
	setenv("TZ", "UTC", 1);
}

LMS1xx::~LMS1xx() {

}

void LMS1xx::connect(std::string host, int port) {
	if (!connected) {
		sockDesc = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (sockDesc) {
			struct sockaddr_in stSockAddr;
			int Res;
			stSockAddr.sin_family = PF_INET;
			stSockAddr.sin_port = htons(port);
			Res = inet_pton(AF_INET, host.c_str(), &stSockAddr.sin_addr);

			int ret = ::connect(sockDesc, (struct sockaddr *) &stSockAddr,
					sizeof stSockAddr);
			if (ret == 0) {
				connected = true;
			}
		}
	}
}

void LMS1xx::disconnect() {
	if (connected) {
		close(sockDesc);
		connected = false;
	}
}

bool LMS1xx::isConnected() {
	return connected;
}

void LMS1xx::startMeas() {
	char buf[100];
	sprintf(buf, "%c%s%c", 0x02, "sMN LMCstartmeas", 0x03);

	write(sockDesc, buf, strlen(buf));

	int len = read(sockDesc, buf, 100);
	//	if (buf[0] != 0x02)
	//		std::cout << "invalid packet recieved" << std::endl;
	//	if (debug) {
	//		buf[len] = 0;
	//		std::cout << buf << std::endl;
	//	}
}

void LMS1xx::stopMeas() {
	char buf[100];
	sprintf(buf, "%c%s%c", 0x02, "sMN LMCstopmeas", 0x03);

	write(sockDesc, buf, strlen(buf));

	int len = read(sockDesc, buf, 100);
	//	if (buf[0] != 0x02)
	//		std::cout << "invalid packet recieved" << std::endl;
	//	if (debug) {
	//		buf[len] = 0;
	//		std::cout << buf << std::endl;
	//	}
}

status_t LMS1xx::queryStatus() {
	char buf[100];
	sprintf(buf, "%c%s%c", 0x02, "sRN STlms", 0x03);

	write(sockDesc, buf, strlen(buf));

	int len = read(sockDesc, buf, 100);
	//	if (buf[0] != 0x02)
	//		std::cout << "invalid packet recieved" << std::endl;
	//	if (debug) {
	//		buf[len] = 0;
	//		std::cout << buf << std::endl;
	//	}
	int ret;
	sscanf((buf + 10), "%d", &ret);

	return (status_t) ret;
}

double LMS1xx::estimateRoundTripTime(struct tcp_info *tcp_info, double alpha, double threshold) {
	char cmd[100];
	char buf[100];
	double delta, y = 0, y_prev = 0;
	struct timespec start, end, diff;
	
	sprintf(cmd, "%c%s%c", 0x02, "sRN SCdevicestate", 0x03);
	do
	{
		y_prev = y;
		clock_gettime(CLOCK_MONOTONIC, &start);
		write(sockDesc, cmd, strlen(cmd));
		int len = read(sockDesc, buf, 100);
		clock_gettime(CLOCK_MONOTONIC, &end);
		diff.tv_sec = end.tv_sec - start.tv_sec;
		diff.tv_nsec = end.tv_nsec - start.tv_nsec;
		delta = diff.tv_sec + (double) diff.tv_nsec/1e9;
		y = (1 - alpha)*y + alpha*delta;
	} while (fabs(y - y_prev) > threshold);
	
	if (tcp_info != NULL)
	{
		socklen_t tcp_info_length = sizeof(*tcp_info);
		getsockopt(sockDesc, SOL_TCP, TCP_INFO, (void *) tcp_info, &tcp_info_length);
	}
	
	return y;
}

int LMS1xx::setTime(double round_trip_time) {
	char cmd[100];
	struct tm *utc_time;
	struct timespec curr_rtime;
	double tt = round_trip_time / 2.;

	clock_gettime(CLOCK_REALTIME, &curr_rtime);
	curr_rtime.tv_nsec += (long) ((tt - (int) tt) * 1e9);
	if (curr_rtime.tv_nsec >= 1000000000L)
	{
		curr_rtime.tv_nsec -= 1000000000L;
		curr_rtime.tv_sec++;
	}
	curr_rtime.tv_sec += (time_t) tt;

	utc_time = gmtime(&curr_rtime.tv_sec);
	sprintf(cmd, "%c%s +%d +%d +%d +%d +%d +%d +%ld%c", 0x02, "sMN LSPsetdatetime",
		utc_time->tm_year+1900, utc_time->tm_mon+1, utc_time->tm_mday,
		utc_time->tm_hour, utc_time->tm_min, utc_time->tm_sec, curr_rtime.tv_nsec/1000, 0x03);

	write(sockDesc, cmd, strlen(cmd));
	int len = read(sockDesc, cmd, 100);
	int ret;
	sscanf(cmd+20 , "%d", &ret);

	return ret;
}

void LMS1xx::login() {
	char buf[100];
	sprintf(buf, "%c%s%c", 0x02, "sMN SetAccessMode 03 F4724744", 0x03);

	write(sockDesc, buf, strlen(buf));

	int len = read(sockDesc, buf, 100);
	//	if (buf[0] != 0x02)
	//		std::cout << "invalid packet recieved" << std::endl;
	//	if (debug) {
	//		buf[len] = 0;
	//		std::cout << buf << std::endl;
	//	}
}

scanCfg LMS1xx::getScanCfg() const {
	scanCfg cfg;
	char buf[100];
	sprintf(buf, "%c%s%c", 0x02, "sRN LMPscancfg", 0x03);

	write(sockDesc, buf, strlen(buf));

	int len = read(sockDesc, buf, 100);
	//	if (buf[0] != 0x02)
	//		std::cout << "invalid packet recieved" << std::endl;
	//	if (debug) {
	//		buf[len] = 0;
	//		std::cout << buf << std::endl;
	//	}

	sscanf(buf + 1, "%*s %*s %X %*d %X %X %X", &cfg.scaningFrequency,
			&cfg.angleResolution, &cfg.startAngle, &cfg.stopAngle);
	return cfg;
}

void LMS1xx::setScanCfg(const scanCfg &cfg) {
	char buf[100];
	sprintf(buf, "%c%s %X +1 %X %X %X%c", 0x02, "sMN mLMPsetscancfg",
			cfg.scaningFrequency, cfg.angleResolution, cfg.startAngle,
			cfg.stopAngle, 0x03);

	write(sockDesc, buf, strlen(buf));

	int len = read(sockDesc, buf, 100);

	buf[len - 1] = 0;
}

int LMS1xx::setIP(unsigned long new_ip) {
	char buf[100];
	unsigned char ip[4];

	for (int i = 0; i < 4; i++) {
		ip[i] = new_ip % 256;
		new_ip >>= 8;
	}
	
	sprintf(buf, "%c%s %X %X %X %X%c", 0x02, "sWN EIIpAddr", ip[0], ip[1], ip[2], ip[3], 0x03);
	
	write(sockDesc, buf, strlen(buf));
	int len = read(sockDesc, buf, 100);

	char command_type[15], command[30];
	int n_read = sscanf(buf, "\x02%s %[^\x03]", command_type, command);
	
	if ((n_read == 2) && (strcmp(command_type, "sWA") == 0) && (strcmp(command, "EIIpAddr") == 0))
		return 1;
	
	return 0;
}

void LMS1xx::setScanDataCfg(const scanDataCfg &cfg) {
	char buf[100];
	sprintf(buf, "%c%s %02X 00 %d %d 0 %02X 00 %d %d 0 %d +%d%c", 0x02,
			"sWN LMDscandatacfg", cfg.outputChannel, cfg.remission ? 1 : 0,
			cfg.resolution, cfg.encoder, cfg.position ? 1 : 0,
			cfg.deviceName ? 1 : 0, cfg.timestamp ? 1 : 0, cfg.outputInterval, 0x03);
	if(debug)
		printf("%s\n", buf);
	write(sockDesc, buf, strlen(buf));

	int len = read(sockDesc, buf, 100);
	buf[len - 1] = 0;
}

void LMS1xx::scanContinous(int start) {
	char buf[100];
	sprintf(buf, "%c%s %d%c", 0x02, "sEN LMDscandata", start, 0x03);

	write(sockDesc, buf, strlen(buf));

	int len = read(sockDesc, buf, 100);

	if (buf[0] != 0x02)
		printf("invalid packet recieved\n");

	if (debug) {
		buf[len] = 0;
		printf("%s\n", buf);
	}

	if (start = 0) {
		for (int i = 0; i < 10; i++)
			read(sockDesc, buf, 100);
	}
}

int LMS1xx::getData(scanData& data) {
	char buf[20000];
	fd_set rfds;
	struct timeval tv;
	int retval, len;
	len = 0;
	bool newRead = true;

	if (q_len)
	{
		memcpy(buf, queue, q_len);
		len = q_len;
		q_len = 0;
		int end;
		for (end = len; buf[end] != 0x03 && end >= 0; end--);
		if (end < len && end > 0)
		{
			newRead = false;
			printf("Collected a part of a next next scan...\n");
			memcpy(queue, buf+end+1, len-end-1);
			q_len = len-end-1;
			len = end+1;
		}
	}
	if (newRead)
	do {
		FD_ZERO(&rfds);
		FD_SET(sockDesc, &rfds);

		tv.tv_sec = 0;
		tv.tv_usec = 50000;
		retval = select(sockDesc + 1, &rfds, NULL, NULL, &tv);
		if (retval) {
			len += read(sockDesc, buf + len, 20000 - len);
		}
		if (buf[0] == 0x02)
		{
			int end;
			for (end = len; buf[end] != 0x03 && end >= 0; end--);
			if (end < len && end > 0)
			{
				//printf("Collected a part of a next scan...\n");
				memcpy(queue, buf+end+1, len-end-1);
				q_len = len-end-1;
				len = end+1;
			}
		}
	} while ((buf[0] != 0x02) || (buf[len - 1] != 0x03));

	//	if (debug)
	//		std::cout << "scan data recieved" << std::endl;
	buf[len - 1] = 0;
	char* tok = strtok(buf, " "); //Type of command
	tok = strtok(NULL, " "); //Command
	tok = strtok(NULL, " "); //VersionNumber
	tok = strtok(NULL, " "); //DeviceNumber
	tok = strtok(NULL, " "); //Serial number
	tok = strtok(NULL, " "); //DeviceStatus
	tok = strtok(NULL, " "); //MessageCounter
	tok = strtok(NULL, " "); //ScanCounter
	tok = strtok(NULL, " "); //PowerUpDuration
	tok = strtok(NULL, " "); //TransmissionDuration
	tok = strtok(NULL, " "); //InputStatus
	tok = strtok(NULL, " "); //OutputStatus
	tok = strtok(NULL, " "); //ReservedByteA
	tok = strtok(NULL, " "); //ScanningFrequency
	tok = strtok(NULL, " "); //MeasurementFrequency
	tok = strtok(NULL, " ");
	tok = strtok(NULL, " ");
	tok = strtok(NULL, " ");
	tok = strtok(NULL, " "); //NumberEncoders
	int NumberEncoders;
	sscanf(tok, "%d", &NumberEncoders);
	for (int i = 0; i < NumberEncoders; i++) {
		tok = strtok(NULL, " "); //EncoderPosition
		tok = strtok(NULL, " "); //EncoderSpeed
	}

	tok = strtok(NULL, " "); //NumberChannels16Bit
	int NumberChannels16Bit;
	sscanf(tok, "%d", &NumberChannels16Bit);
	if (debug)
		printf("NumberChannels16Bit : %d\n", NumberChannels16Bit);
	for (int i = 0; i < NumberChannels16Bit; i++) {
		int type = -1; // 0 DIST1 1 DIST2 2 RSSI1 3 RSSI2
		char content[6];
		tok = strtok(NULL, " "); //MeasuredDataContent
		sscanf(tok, "%s", content);
		if (!strcmp(content, "DIST1")) {
			type = 0;
		} else if (!strcmp(content, "DIST2")) {
			type = 1;
		} else if (!strcmp(content, "RSSI1")) {
			type = 2;
		} else if (!strcmp(content, "RSSI2")) {
			type = 3;
		}
		tok = strtok(NULL, " "); //ScalingFactor
		tok = strtok(NULL, " "); //ScalingOffset
		tok = strtok(NULL, " "); //Starting angle
		tok = strtok(NULL, " "); //Angular step width
		tok = strtok(NULL, " "); //NumberData
		int NumberData;
		sscanf(tok, "%X", &NumberData);

		if (debug)
			printf("NumberData : %d\n", NumberData);

		if (type == 0) {
			data.dist_len1 = NumberData;
		} else if (type == 1) {
			data.dist_len2 = NumberData;
		} else if (type == 2) {
			data.rssi_len1 = NumberData;
		} else if (type == 3) {
			data.rssi_len2 = NumberData;
		}

		for (int i = 0; i < NumberData; i++) {
			int dat;
			tok = strtok(NULL, " "); //data
			sscanf(tok, "%X", &dat);

			if (type == 0) {
				data.dist1[i] = dat;
			} else if (type == 1) {
				data.dist2[i] = dat;
			} else if (type == 2) {
				data.rssi1[i] = dat;
			} else if (type == 3) {
				data.rssi2[i] = dat;
			}

		}
	}

	tok = strtok(NULL, " "); //NumberChannels8Bit
	int NumberChannels8Bit;
	sscanf(tok, "%d", &NumberChannels8Bit);
	if (debug)
		printf("NumberChannels8Bit : %d\n", NumberChannels8Bit);
	for (int i = 0; i < NumberChannels8Bit; i++) {
		int type = -1;
		char content[6];
		tok = strtok(NULL, " "); //MeasuredDataContent
		sscanf(tok, "%s", content);
		if (!strcmp(content, "DIST1")) {
			type = 0;
		} else if (!strcmp(content, "DIST2")) {
			type = 1;
		} else if (!strcmp(content, "RSSI1")) {
			type = 2;
		} else if (!strcmp(content, "RSSI2")) {
			type = 3;
		}
		tok = strtok(NULL, " "); //ScalingFactor
		tok = strtok(NULL, " "); //ScalingOffset
		tok = strtok(NULL, " "); //Starting angle
		tok = strtok(NULL, " "); //Angular step width
		tok = strtok(NULL, " "); //NumberData
		int NumberData;
		sscanf(tok, "%X", &NumberData);

		if (debug)
			printf("NumberData : %d\n", NumberData);

		if (type == 0) {
			data.dist_len1 = NumberData;
		} else if (type == 1) {
			data.dist_len2 = NumberData;
		} else if (type == 2) {
			data.rssi_len1 = NumberData;
		} else if (type == 3) {
			data.rssi_len2 = NumberData;
		}
		for (int i = 0; i < NumberData; i++) {
			int dat;
			tok = strtok(NULL, " "); //data
			sscanf(tok, "%X", &dat);

			if (type == 0) {
				data.dist1[i] = dat;
			} else if (type == 1) {
				data.dist2[i] = dat;
			} else if (type == 2) {
				data.rssi1[i] = dat;
			} else if (type == 3) {
				data.rssi2[i] = dat;
			}
		}
	}
	
	int flag;
	tok = strtok(NULL, " "); // Position
	sscanf(tok, "%d", &flag);
	if (flag)
	  for(int i = 0; i < 7; i++) tok = strtok(NULL, " ");
	tok = strtok(NULL, " "); // Name
	sscanf(tok, "%d", &flag);
	if (flag) tok = strtok(NULL, " ");
	tok = strtok(NULL, " "); // Comment
	sscanf(tok, "%d", &flag);
	if (flag) tok = strtok(NULL, " ");
	tok = strtok(NULL, " "); // Time
	sscanf(tok, "%d", &flag);
	struct tm lms_time;
	lms_time.tm_isdst = -1;
	if (flag) {
	  tok = strtok(NULL, " ");
	  sscanf(tok, "%X", &lms_time.tm_year);
	  tok = strtok(NULL, " ");
	  sscanf(tok, "%X", &lms_time.tm_mon);
	  tok = strtok(NULL, " ");
	  sscanf(tok, "%X", &lms_time.tm_mday);
	  tok = strtok(NULL, " ");
	  sscanf(tok, "%X", &lms_time.tm_hour);
	  tok = strtok(NULL, " ");
	  sscanf(tok, "%X", &lms_time.tm_min);
	  tok = strtok(NULL, " ");
	  sscanf(tok, "%X", &lms_time.tm_sec);
	  tok = strtok(NULL, " ");
	  sscanf(tok, "%X", &data.timestamp.tv_usec);
	  lms_time.tm_year -= 1900;
	  lms_time.tm_mon--;
	  data.timestamp.tv_sec = mktime(&lms_time);
	}
	
  return 0;
}

int LMS1xx::saveConfig() {
	char buf[100];
	sprintf(buf, "%c%s%c", 0x02, "sMN mEEwriteall", 0x03);

	write(sockDesc, buf, strlen(buf));

	int len = read(sockDesc, buf, 100);
	int n_read, status;
	n_read = sscanf(buf, "\x02sAN mEEwriteall %d\x03", &status);
	if (n_read == 1 && status == 1)
		return 1;
	return 0;
	//	if (buf[0] != 0x02)
	//		std::cout << "invalid packet recieved" << std::endl;
	//	if (debug) {
	//		buf[len] = 0;
	//		std::cout << buf << std::endl;
	//	}
}

int LMS1xx::reboot() {
	char buf[100];
	sprintf(buf, "%c%s%c", 0x02, "sMN mSCreboot", 0x03);

	write(sockDesc, buf, strlen(buf));

	int len = read(sockDesc, buf, 100);
	char command_type[15], command[30];
	int n_read = sscanf(buf, "\x02%s %[^\x03]", command_type, command);
	if ((n_read == 2) && (strcmp(command_type, "sAN") == 0) && (strcmp(command, "mSCreboot") == 0))
		return 1;
	
	return 0;
}

void LMS1xx::startDevice() {
	char buf[100];
	sprintf(buf, "%c%s%c", 0x02, "sMN Run", 0x03);

	write(sockDesc, buf, strlen(buf));

	int len = read(sockDesc, buf, 100);
	//	if (buf[0] != 0x02)
	//		std::cout << "invalid packet recieved" << std::endl;
	//	if (debug) {
	//		buf[len] = 0;
	//		std::cout << buf << std::endl;
	//	}
}
