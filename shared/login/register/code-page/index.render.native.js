// @flow
/*
 * Screen to scan/show qrcode/text code. Goes into various modes with various options depending on if
 * you're a phone/computer and if you're the existing device or the new device
 */

import Container from '../../forms/container'
import {isIOS} from '../../../constants/platform'
import Qr from './qr'
import React, {Component} from 'react'
import {Box, Button, ClickableBox, Icon, Input, NativeStyleSheet, TabBar, Text} from '../../../common-adapters/index.native'
import {TabBarItem} from '../../../common-adapters/tab-bar'
import {codePageDeviceRoleExistingPhone, codePageModeScanCode, codePageModeShowCode, codePageModeEnterText, codePageModeShowText} from '../../../constants/login'
import {globalStyles, globalColors} from '../../../styles'

import type {IconType} from '../../../common-adapters/icon'
import type {Mode} from '../../../constants/login'
import type {Props} from './index.render'

class CodePageRender extends Component<void, Props, void> {

  renderShowCode () {
    return (
      <Qr
        style={{alignItems: 'center', justifyContent: 'center', flexDirection: 'column'}}
        scanning={false}
        onBarCodeRead={() => {}}
        qrCode={this.props.qrCode} />
    )
  }

  renderScanCode () {
    return (
      <Qr
        scanning={true}
        onBarCodeRead={code => this.props.qrScanned(code)}
        style={stylesQRScan}
        qrCode={this.props.qrCode}>

        {isIOS &&
          <Box style={{alignSelf: 'center', width: 200, height: 200}}>
            <Box style={[stylesScan.box, stylesScan.boxEdge, {left: 0}]} />
            <Box style={[stylesScan.box, stylesScan.boxEdge, {right: 0}]} />
            <Box style={[stylesScan.box, stylesScan.boxCorner, {right: 0, top: 0}]} />
            <Box style={[stylesScan.box, stylesScan.boxCorner, {left: 0, top: 0}]} />
            <Box style={[stylesScan.box, stylesScan.boxCorner, {right: 0, bottom: 0}]} />
            <Box style={[stylesScan.box, stylesScan.boxCorner, {left: 0, bottom: 0}]} />
          </Box>}
      </Qr>
    )
  }

  renderShowText () {
    return (
      <Box style={stylesShowText}>
        <Text type='Header' style={stylesTextCode}>{this.props.textCode}</Text>
      </Box>
    )
  }

  renderEnterText () {
    return (
      <Box style={stylesEnterText}>
        <Icon type='icon-phone-text-code-32' style={{alignSelf: 'center'}} />
        <Input
          hintText='opp blezzard tofi pando agg whi pany yaga jocket daubt bruwnstane hubit yas'
          floatingHintTextOverride='Text code'
          multiline={true}
          rowsMin={3}
          value={this.props.enterText}
          onChangeText={text => this.props.onChangeText(text)}
        />
        <Button type='Primary' style={{marginTop: 10, marginBottom: 20}} label='Continue' onClick={() => this.props.textEntered(codePageModeEnterText)} />
      </Box>
    )
  }

  renderSwitchButton (mode: Mode, icon: IconType, label: string) {
    return (
      <ClickableBox
        underlayColor={globalColors.white}
        onClick={() => this.props.setCodePageMode(mode)}
        style={{marginBottom: 20}}>
        <Box style={{...globalStyles.flexBoxRow, alignItems: 'center', alignSelf: 'center', marginLeft: 10, marginRight: 10}}>
          <Icon type={icon} />
          <Text type='BodyBigLink' style={{marginLeft: 4}}>{label}</Text>
        </Box>
      </ClickableBox>
    )
  }

  renderScanCodeForDesktop () {
    return (
      <Container style={stylesContainer} onBack={this.props.onBack}>
        <Box style={stylesIntro}>
          <Text type='Header' style={{marginBottom: 10}}>Scan QR code</Text>
          <Text type='Body'>In the Keybase app on your computer,</Text>
          <Text type='Body'>{'go to Devices > Add a new device.'}</Text>
        </Box>
        {this.renderScanCode()}
        {this.renderSwitchButton(codePageModeEnterText, 'icon-phone-text-code-32', 'Type text code instead')}
      </Container>
    )
  }

  renderShowCodeForDesktop () {
    return (
      <Container style={stylesContainer} onBack={this.props.onBack}>
        <Box style={stylesIntro}>
          <Text type='Header' style={{marginBottom: 10}}>Scan QR code</Text>
          <Text type='Body'>{'When adding a new mobile device.'}</Text>
        </Box>
        {this.renderShowCode()}
        {this.renderSwitchButton(codePageModeShowText, 'icon-phone-text-code-32', 'Type text code instead')}
      </Container>
    )
  }

  renderCodeForMobile () {
    return (
      <Container style={stylesContainer} onBack={this.props.onBack}>
        <Box style={stylesIntro}>
          <Text type='Header' style={{marginBottom: 10}}>Scan QR code</Text>
          <Text type='Body'>In the Keybase app</Text>
          <Text type='Body'>{'go to Devices > Add a new device.'}</Text>
        </Box>
        <TabBar style={{flex: 1}}>
          <TabBarItem
            selected={this.props.mode === codePageModeShowCode}
            label='Display Code'
            onClick={() => { this.props.setCodePageMode(codePageModeShowCode) }}>
            {this.renderShowCode()}
          </TabBarItem>
          <TabBarItem
            label='Scan Code'
            selected={this.props.mode === codePageModeScanCode}
            onClick={() => { this.props.setCodePageMode(codePageModeScanCode) }}>
            {this.renderScanCode()}
          </TabBarItem>
        </TabBar>
        {this.renderSwitchButton(codePageModeEnterText, 'icon-phone-text-code-32', 'Type text code instead')}
      </Container>
    )
  }

  renderShowTextForDesktop () {
    return (
      <Container style={stylesContainer} onBack={this.props.onBack}>
        <Box style={stylesIntro}>
          <Text type='Header' style={{marginBottom: 10}}>Type in text code</Text>
          <Text type='Body'>Please run</Text>
          <Text type='TerminalInline' backgroundMode='Terminal'>keybase device add</Text>
          <Text type='Body'>in the terminal on your computer.</Text>
        </Box>
        {this.renderShowText()}
        {this.renderSwitchButton(codePageModeShowCode, 'icon-phone-qr-code-48', 'Scan QR code instead')}
      </Container>
    )
  }

  renderEnterTextForDesktop () {
    return (
      <Container style={stylesContainer} onBack={this.props.onBack}>
        <Box style={stylesIntro}>
          <Text type='Header'>Type in text code</Text>
        </Box>
        {this.renderEnterText()}
        {this.renderSwitchButton(codePageModeScanCode, 'icon-phone-qr-code-48', 'Scan QR code instead')}
      </Container>
    )
  }

  renderTextForMobile () {
    return (
      <Container style={stylesContainer} onBack={this.props.onBack}>
        <Box style={stylesIntro}>
          <Text type='Header' style={{marginBottom: 10}}>Type text code</Text>
          <Text type='Body'>In the Keybase App</Text>
          <Text type='Body'>{'go to Devices > Add a new device.'}</Text>
        </Box>
        <TabBar underlined={true} style={{flex: 1}}>
          <TabBarItem
            selected={this.props.mode === codePageModeShowText}
            label='Display Code'
            onClick={() => { this.props.setCodePageMode(codePageModeShowText) }}>
            {this.renderShowText()}
          </TabBarItem>
          <TabBarItem
            label='Type Code'
            selected={this.props.mode === codePageModeEnterText}
            onClick={() => { this.props.setCodePageMode(codePageModeEnterText) }}>
            {this.renderEnterText()}
          </TabBarItem>
        </TabBar>
        {this.renderSwitchButton(codePageModeScanCode, 'icon-phone-qr-code-48', 'Scan QR code instead')}
      </Container>
    )
  }

  render () {
    let otherDeviceIsMobile = this.props.otherDeviceRole === codePageDeviceRoleExistingPhone
    switch (this.props.mode) {
      case codePageModeShowCode:
        if (otherDeviceIsMobile) {
          return this.renderCodeForMobile()
        }
        return this.renderShowCodeForDesktop()

      case codePageModeScanCode:
        if (otherDeviceIsMobile) {
          return this.renderCodeForMobile()
        }
        return this.renderScanCodeForDesktop()

      case codePageModeShowText:
        if (otherDeviceIsMobile) {
          return this.renderTextForMobile()
        }
        return this.renderShowTextForDesktop()

      case codePageModeEnterText:
        if (otherDeviceIsMobile) {
          return this.renderTextForMobile()
        }
        return this.renderEnterTextForDesktop()
    }
  }
}

const stylesContainer = {
  ...globalStyles.flexBoxColumn,
  flex: 1,
  alignItems: 'stretch',
  justifyContent: 'flex-start',
}

const stylesIntro = {
  marginTop: 30,
  alignItems: 'center',
  marginBottom: 20,
}

const stylesEnterText = {
  ...globalStyles.flexBoxColumn,
  flex: 1,
  justifyContent: 'center',
  padding: 20,
}

const stylesShowText = {
  ...globalStyles.flexBoxColumn,
  flex: 1,
  justifyContent: 'center',
  marginTop: 10,
  marginBottom: 10,
  padding: 32,
}

const stylesTextCode = {
  ...globalStyles.selectable,
  ...globalStyles.fontTerminal,
  color: globalColors.darkBlue,
  textAlign: 'center',
}

const stylesQRScan = {
  height: 200,
  marginBottom: 20,
}

const stylesScan = NativeStyleSheet.create({
  box: {
    backgroundColor: 'red',
    position: 'absolute',
  },
  boxCorner: {
    height: 1,
    width: 20,
  },
  boxEdge: {
    top: 0,
    bottom: 0,
    width: 1,
  },
})

export default CodePageRender
